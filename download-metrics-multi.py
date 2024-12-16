import argparse
import dateutil
import logging
import math
import os
import pprint
import psycopg2
import pyasn
import select
import setproctitle
import subprocess
import sys
import time

from IPy import IP as ipadd
from crc64iso.crc64iso import crc64
from datetime import datetime
from geohash2 import encode
from geoip import geolite2
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBServerError, InfluxDBClientError
from multiprocessing import Pool, Process, Queue, TimeoutError, Event, Manager
from multiprocessing import set_start_method
from os import environ as env, stat
from platform import uname
from re import compile, match, search, sub, IGNORECASE
from time import sleep, time
from urllib.parse import urlparse

#
# global variables
#

log_path = "/var/log/nginx_collected/access.log"

time_offset_count = 0
time_offset_count_limit = 2000

monitored_ip_types = [
        'PUBLIC',
        'ALLOCATED APNIC',
        'ALLOCATED ARIN',
        'ALLOCATED RIPE NCC',
        'ALLOCATED LACNIC',
        'ALLOCATED AFRINIC'
        ]

# regular expressions
#   split a standard 0.0.0.0 IPv4 address
format_ipv4 = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
#   split an IPv6 address
format_ipv6 = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

# on host logs:
# 2a01:4f8:c17:5333::1 - - [06/May/2022:13:43:43 -0700] "GET /manjaro/unstable/state HTTP/1.1" 200 276 "-" "Python-urllib/3.6" "0.000" "-" "-" "-" "-"
# 66.17.221.29 - - [06/May/2022:13:43:43 -0700] "GET /centos/7.9.2009/updates/x86_64/Packages/systemd-libs-219-78.el7_9.5.x86_64.rpm HTTP/1.1" 200 428820 "-" "urlgrabber/3.10 yum/3.4.3" "0.143" "-" "US" "United States" "-"
#
# logs sent via syslog:
# May  6 13:41:21 griffin1 griffin1 nginx_access: 66.187.232.129 - - [06/May/2022:13:41:21 -0700] "GET /fedora-archive/fedora/linux/updates/31/Everything/x86_64/repodata/repomd.xml HTTP/1.1" 200 8312 "-" "libdnf (Fedora 31; container; Linux.x86_64)" "0.001" "-" "US" "United States" "-"

mc_syslog_datetime	= r'(?P<syslog_datetime>^[A-Za-z]{3}\s{1,}\d{1,}\s{1,}\d{1,}:\d{1,}:\d{1,})'
mc_syslog_host1		= r'(?P<syslog_host1>.+)'
mc_syslog_host2		= r'(?P<syslog_host2>.+)'

mc_ipv4                 = r'(?P<ipaddress>{})'.format( format_ipv4 )
mc_ipv6                 = r'(?P<ipaddress>{})'.format( format_ipv6 )
mc_remote_user          = r'(?P<remote_user>.+)'
mc_dateandtime          = r'(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))'
mc_method               = r'(?P<method>.+)'
mc_referrer             = r'(?P<referrer>.+)'
mc_http_version         = r'(?P<http_version>HTTP\/[1-3]\.[0-9])'
mc_status_code          = r'(?P<status_code>\d{3})'
mc_bytes_sent           = r'(?P<bytes_sent>\d{1,99})'
mc_url                  = r'(?P<url>(\-)|(.+))'
mc_host                 = r'(?P<host>.+)'
mc_user_agent           = r'(?P<user_agent>.+)'
mc_request_time         = r'(?P<request_time>(?:\d+\.?\d*|\d+|-))'
mc_request_connect_time = r'(?P<request_connect_time>(?:\d+\.?\d*|\d+|-))'
mc_country_code         = r'(?P<country_code>.+)'
mc_country_code_name    = r'(?P<country_code_name>.+)'
mc_ssl                  = r'(?P<ssl>.+)'

re_log_line_common_str = r'{remote_user} \[{dateandtime}\] "{method} {url} {http_version}" {status_code} {bytes_sent} "{referrer}" ["]{user_agent}["] ["]{request_time}["] ["]{request_connect_time}["] ["]{country_code}["] ["]{country_code_name}["] ["]{ssl}["]'.format(
        remote_user = mc_remote_user,
        dateandtime = mc_dateandtime,
        method = mc_method,
        referrer = mc_referrer,
        http_version = mc_http_version,
        status_code = mc_status_code,
        bytes_sent = mc_bytes_sent,
        url = mc_url,
        host = mc_host,
        user_agent = mc_user_agent,
        request_time = mc_request_time,
        request_connect_time = mc_request_connect_time,
        country_code = mc_country_code,
        country_code_name = mc_country_code_name,
        ssl = mc_ssl
        )

re_syslog_prefix = r'{syslog_datetime} {syslog_host1} {syslog_host2} nginx_access:'.format(
	syslog_datetime = mc_syslog_datetime,
	syslog_host1 = mc_syslog_host1,
	syslog_host2 = mc_syslog_host2,
        )

re_ipv4_str = r'{syslog_prefix} {ipv4}'.format(
        syslog_prefix = re_syslog_prefix,
        ipv4 = mc_ipv4
        )

re_ipv6_str = r'{syslog_prefix} {ipv6}'.format(
        syslog_prefix = re_syslog_prefix,
        ipv6 = mc_ipv6
        )

re_log_line_v4_str = r'{v4_str} - {common}'.format(
        v4_str = re_ipv4_str,
        common = re_log_line_common_str
        )

re_log_line_v6_str = r'{v6_str} - {common}'.format(
        v6_str = re_ipv6_str,
        common = re_log_line_common_str
        )


re_ipv4 = compile( re_ipv4_str, IGNORECASE) # NOQA
re_ipv6 = compile( re_ipv6_str, IGNORECASE) # NOQA

re_log_line_v4 = compile( re_log_line_v4_str, IGNORECASE) # NOQA
re_log_line_v6 = compile( re_log_line_v6_str, IGNORECASE) # NOQA

#
# Ok end of variables
# Begin the overall defines
#


pp = pprint.PrettyPrinter(indent=4)
#set_start_method("spawn")

#
# End the overall defines
#

# hex string to signed integer
def hex_to_sint(val):
    uintval = int(val,16)
    bits = 4 * (len(val) - 2)
    if uintval >= math.pow(2,bits-1):
        uintval = int(0 - (math.pow(2,bits) - uintval))
    return uintval

def getSignedNumber(number, bitLength):
    mask = (2 ** bitLength) - 1
    if number & (1 << (bitLength - 1)):
        return number | ~mask
    else:
        return number & mask

def parseline(
        pid,
        line,
        client_telegraf,
        pg_conn,
        pg_cursor,
        logging,
        asndb,
        log_measurement,
        args
        ):
    global re_ipv4
    global re_ipv6
    global time_offset_count
    global time_offset_count_limit


    if type(line) is not str:
        try:
            # ok SOMETIMES people chuck garbage in the line, no idea why / how
            # so try it, if it fails, skip it.
            line = line.decode("utf-8", 'ignore')
        except Exception as e:
            logging.error('Line is not valid utf-8 |{}| - {}'.format( line, e ) )
            return

    # Preparing variables and params
    ips = {}
    geohash_fields = {}
    geohash_tags = {}
    log_data_fields = {}
    log_data_tags = {}
    nginx_log = {}
    log_hash = {}
    hostname = uname()[1]

    geo_metrics = []
    log_metrics = []
    #print( '    pre-check Line: '+ line.rstrip(), flush=true )
    #print( "V4: "+ str(re_ipv4.match(line)), flush=true )
    #print( "V6: "+ str(re_ipv6.match(line)), flush=true )
    if "nginx_error: " in line:
        #continue
        return
    if "2: No such file or directory" in line:
        #continue
        return
    if "SSL_read() failed" in line:
        #continue
        return
    if len(line) <= 1:
        #continue
        return
    if "\\" in line:
        #continue
        return

    if re_ipv4.match(line):
        m = re_ipv4.match(line)
        ip = m.group(4)
        log = re_ipv4
        log = re_log_line_v4
        ip_type_str = "IPv4"
        ip_type_num = 4
    elif re_ipv6.match(line):
        m = re_ipv6.match(line)
        ip = m.group(4)
        log = re_ipv6
        log = re_log_line_v6
        ip_type_str = "IPv6"
        ip_type_num = 6
    else:
                    #line = line.rstrip(),
        #warn_str = "Failed to match regex that previously matched!? Skipping this line! |{line}| len: {length}\n".format(
        warn_str = "Failed to match regex that previously matched!? Skipping this line! len: {length}\n".format(
                    length = len(line),
                    )
        #print( warn_str )
        #print( "\n" )
        logging.warning( warn_str )

        ip_type_str = "-"
        #quit()
        #continue
        return

    ip_type = ipadd(ip).iptype()
    if ip_type in monitored_ip_types and ip:
        #info = gi.city(ip)
        info = geolite2.lookup(ip)
        # its possible this is none?

        #
        # This is just nginx log file data
        #

        data = search(log, line)

        if data is None:
            err_str = "*** Error in line - continuing || len: {length}\n".format(
                    line = line.rstrip(),
                    length = len(line),
                    )
            #print( err_str )
            #print("\n" )
            logging.warning( err_str )
            #continue
            return

        asn = asndb.lookup( ip )

        asn_name = asndb.get_as_name( asn[0] )

        datadict = data.groupdict()
        purl = urlparse( datadict['url'] )
        purl_path = purl.path

        if "%2F" in purl_path:
            purl_path = purl_path.replace( "%2F", "/" )

        spurl = purl_path.split("/")
        #print("\tIP: "+ ip +' | Url: '+ datadict['url'] +' | Spurl length:'+ str( len( spurl ) ) ) 
        distro = spurl[1] if len( spurl ) > 1 else "-"
        distro_version = spurl[2] if len( spurl ) > 2 else "-"
        if distro == "fedora":
            # Fedora will "always" have '/linux/' as the second part of the url
            # there fore we don't actually care...
            # basically we need
            # /fedora/linux/<type>/<version> with fedora so it's actually 
            # going to have a version associated with it
            distro_version = spurl[4] if len( spurl ) > 4 else "-"

        if distro == "fedora-archive":
            # this is a bit of a special case
            distro_version = spurl[5] +"-"+ spurl[6] if len( spurl )> 6 else "-"
            distro_version = spurl[5] if len( spurl ) > 5 else "-"

        if len( distro ) >= 20:
            distro = distro[0:17] +"..."

        if len( distro_version ) >= 20:
            distro = distro[0:17] +"..."

        #if datadict['syslog_host1'] == 'codingflyboy.mm.fcix.net' and distro != 'epel':
        #    print("Line: "+ line )
        #    print("from_host: "+ datadict['syslog_host1'] +" | Distro:"+ distro)

        log_data_fields['count'] = int(1)
        log_data_fields['bytes_sent'] = int(datadict['bytes_sent'])
        #log_data_tags['ip'] = datadict['ipaddress']
        #log_data_tags['datetime'] = datetime.strptime(datadict['dateandtime'], '%d/%b/%Y:%H:%M:%S %z')

        #print( "--- Checking dates ---" )
        datestr = datetime.strptime(
                    datadict['dateandtime'],
                    '%d/%b/%Y:%H:%M:%S %z'
                    )

        # Check if we are dealing with a bounded date
        if args.date_before is not None:
            date_before = dateutil.parser.parse(args.date_before[0])
            #pp.pprint( datestr )
            #pp.pprint( date_before )

        if args.date_after is not None:
            date_after = dateutil.parser.parse(args.date_after[0])
            #pp.pprint( datestr )
            #pp.pprint( date_after )

        if args.date_before and args.date_after:
            #print(
            #        "before: datestr {} < dbefore {}: {}".format(
            #            datestr.timestamp(),
            #            date_before.timestamp(),
            #            datestr.timestamp() > date_before.timestamp()
            #            )
            #        )
            if (
                datestr.timestamp() > date_before.timestamp()
                and
                datestr.timestamp() < date_after.timestamp()
                ):
                #print( "before and after returning" )
                return

        elif args.date_before:
            #print(
            #        "before: datestr {} < dbefore {}: {}".format(
            #            datestr.timestamp(),
            #            date_before.timestamp(),
            #            datestr.timestamp() > date_before.timestamp()
            #            )
            #        )
            if datestr.timestamp() > date_before.timestamp():
                #print( "before and after returning" )
                return

        elif args.date_after:
            #print(
            #        "after: datestr {} > d fter{}: {}".format(
            #            datestr.timestamp(),
            #            date_after.timestamp(),
            #            datestr.timestamp() > date_after.timestamp()
            #            )
            #        )
            if datestr.timestamp() < date_after.timestamp():
                #print( "after returning" )
                return

        #print( line )

        timestamp_dt = datetime.timestamp( datestr )
        timestamp = int( timestamp_dt )

        time_offset_count = time_offset_count + 1

        if time_offset_count > time_offset_count_limit:
            nowdt = datetime.now().astimezone()
            deltadt = nowdt - datestr
            logging.info("{} - Current Time lag: {}".format( pid, deltadt ) )
            time_offset_count = 0

        #log_data_tags['remote_user'] = datadict['remote_user']
        log_data_tags['method'] = datadict['method']
        #log_data_tags['referrer'] = datadict['referrer']
        log_data_tags['host'] = datadict['host'] if 'host' in datadict else "-"
        log_data_tags['http_version'] = datadict['http_version']
        log_data_tags['status_code'] = int(datadict['status_code'])
        #log_data_tags['bytes_sent'] = datadict['bytes_sent']
        #log_data_tags['url'] = datadict['url']
        log_data_tags['from_host'] = datadict['syslog_host1']

        #
        # Ok lets talk about User Agent!
        # It's a mostly free form field that people have a tendency
        # to shove nearly useless things into!  In this case
        # Mock, the fedora / epel build system seemingly shoves it's
        # builder + build id into the user agent string. I mean that's
        # "useful" but, ugh, obnoxious lets chop it off
        #
        user_agent = datadict['user_agent']
        if user_agent.startswith('Mock '):
            user_agent = sub( r'-[0-9]+\.[0-9]+;.*\)$', '', user_agent ) + ")"
            #print("user_agent: "+ user_agent )

        log_data_tags['user_agent'] = user_agent

        log_data_tags['geo_country_code'] = datadict['country_code']
        #if info is not None:
        #    if info.subdivisions:
        #        for state in info.subdivisions:
        #            garbage = state
        #            #print( state )
        #        log_data_tags['geo_state'] = state if state else "-"

        log_data_tags['asn'] = int(asn[0]) if asn[0] is not None else "-"
        log_data_tags['asn_name'] = asn_name
        log_data_tags['ssl'] = datadict['ssl']

        log_data_tags['distro'] = distro
        log_data_tags['distro_version'] = distro_version
        #log_data_tags['ip_type'] = ip_type_str
        log_data_tags['ip_type'] = int(ip_type_num)

        # create dict
        nginx_log['tags'] = log_data_tags
        nginx_log['fields'] = log_data_fields
        nginx_log['measurement'] = log_measurement
        nginx_log['time'] = timestamp

        # create line format
        str_tags = ','.join(f'{k}="{v}"' for k, v in log_data_tags.items())
        str_fields = ','.join(f'{k}={v}' for k, v in log_data_fields.items())

        line_protocol = "{measurement},{tags} {fields} {timestamp}".format(
                measurement = log_measurement,
                tags = str_tags,
                fields = str_fields,
                timestamp = timestamp
                )
        #print("line_protocol: "+ line_protocol )

        log_metrics.append(nginx_log)
        #log_metrics.append(line_protocol)

        ##tagval = "{measurement},{tags} {timestamp}".format(
        ##        measurement = log_measurement,
        ##        tags = str_tags,
        ##        timestamp = timestamp
        ##        )
        ##
        ##if tagval not in log_hash:
        ##    log_hash[tagval] = {}
        ##    log_hash[tagval]['fields'] = {}
        ##
        ##for field in log_data_fields:
        ##    if field not in log_hash[tagval]['fields']:
        ##        log_hash[tagval]['fields'][field] = 0
        ##
        ##    log_hash[tagval]['fields'][field] += log_data_fields[field]
        ##
        ##log_hash[tagval]['nginx_log'] = nginx_log
        ##log_hash[tagval]['tags'] = log_data_tags
        ##log_hash[tagval]['measurement'] = log_measurement
        ##log_hash[tagval]['time'] = timestamp

        logging.debug(f'NGINX log metrics: {log_metrics}')

        log_metrics_len = len( log_metrics )
        ##log_metrics_len = len( log_hash )
        #pp = pprint.PrettyPrinter(indent=4)
        #if datadict['syslog_host1'] == 'codingflyboy.mm.fcix.net' and distro != 'epel':
        #    pp.pprint( nginx_log )

        #if log_metrics_len > 10:
        #if log_metrics_len > 100:
        if True:
            ##log_metrics = []
            ##for tagval in log_hash:
            ##    nginx_log['tags'] = log_hash[tagval]['tags']
            ##    nginx_log['fields'] = log_hash[tagval]['fields']
            ##    nginx_log['measurement'] = log_hash[tagval]['measurement']
            ##    nginx_log['time'] = log_hash[tagval]['time']
            ##    log_metrics.append( nginx_log )
            ##log_hash = {}

            #print("Committing to Influx")
            #pp.pprint( log_metrics )
            #exit()
##                        try:
##                            client.write_points(
##                                    log_metrics,
##                                    time_precision='s',
##                                    #protocol='json',
##                                    #protocol='line',
##                                    )
##                        except (InfluxDBServerError, InfluxDBClientError, ConnectionError) as e:
##                            logging.error('Error writing data to InfluxDB! Check your database!\n'
##                                        f'Error: {e}'
##                                        )
##                        try:
##                            client_reduce.write_points(
##                                    log_metrics,
##                                    time_precision='s',
##                                    #protocol='json',
##                                    #protocol='line',
##                                    )
##                        except (InfluxDBServerError, InfluxDBClientError, ConnectionError) as e:
##                            logging.error('Error writing data to InfluxDB! Check your database!\n'
##                                        f'Error: {e}'
##                                        )
            try:
                #nginx_log['time'] = timestamp * 1e9
                #tzoffset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
                #nginx_log['time'] = ( timestamp + tzoffset ) * 1000000000
                nginx_log['time'] = timestamp * 1000000000
                log_metrics.append(nginx_log)

                client_telegraf.write_points(
                        log_metrics,
                        #time_precision='s',
                        #protocol='json',
                        #protocol='line',
                        )
            except (InfluxDBServerError, InfluxDBClientError, ConnectionError) as e:
                logging.error('Error writing data to Telegraf! Check your database!\n'
                            f'Error: {e}'
                            )

            try:
                sql_find_meta = """SELECT
                    tag_id
                FROM
                    telegraf.sql_nginx_access_logs_tag
                WHERE
                    asn = %s
                    AND
                    asn_name = %s
                    AND
                    distro = %s
                    AND
                    distro_version = %s
                    AND
                    from_host = %s
                    AND
                    geo_country_code = %s
                    AND
                    host = %s
                    AND
                    http_version = %s
                    AND
                    ip_type = %s
                    AND
                    method = %s
                    AND
                    ssl = %s
                    AND
                    status_code = %s
                    AND
                    user_agent = %s;
                    """
                sql_insert_meta = """INSERT
                INTO
                    telegraf.sql_nginx_access_logs_tag
                (
                    tag_id,
                    asn,
                    asn_name,
                    distro,
                    distro_version,
                    from_host,
                    geo_country_code,
                    host,
                    http_version,
                    ip_type,
                    method,
                    ssl,
                    status_code,
                    user_agent
                )
                VALUES(
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                ON CONFLICT
                DO NOTHING
                RETURNING tag_id;
                    """

                sql_insert_counts = """
                    INSERT
                    INTO
                        telegraf.sql_nginx_access_logs
                    (
                        time,
                        tag_id,
                        bytes_sent,
                        count
                    )
                    VALUES
                    (
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """

                sql_meta_data = (
                            str(log_data_tags['asn']),
                            log_data_tags['asn_name'],
                            log_data_tags['distro'],
                            log_data_tags['distro_version'],
                            log_data_tags['from_host'],
                            log_data_tags['geo_country_code'],
                            log_data_tags['host'],
                            log_data_tags['http_version'],
                            str(log_data_tags['ip_type']),
                            log_data_tags['method'],
                            log_data_tags['ssl'],
                            str(log_data_tags['status_code']),
                            log_data_tags['user_agent'],
                            )

                if sql_meta_data == None:
                        return

                #sql_meta_data_hash = getSignedNumber(
		#	hex_to_sint(
                #        	crc64(
                #            		','.join(sql_meta_data)
	        #                    )
        	#                ),
		#	64
		#	)

                #sql_meta_data_list = list( sql_meta_data )
                #sql_meta_data_list.insert( 0, sql_meta_data_hash )
                #sql_meta_data = tuple( sql_meta_data_list )

                dt_obj = datetime.fromtimestamp(timestamp)

                #sql_count_data = (
                #        dt_obj,
                #        sql_meta_data_hash,
                #        log_data_fields['bytes_sent'],
                #        int(1)
                #        )

                sql_enable = False
                if sql_enable == True:
                    #pg_cursor.execute(
                    #        sql_find_meta,
                    #        sql_meta_data
                    #        )
                    #
                    #found_tag_id = None
                    #for tag_id in pg_cursor:
                    #    #print( "found tag id: {}".format(tag_id) )
                    #    found_tag_id = tag_id
                    
                    #if not found_tag_id:
                    pg_cursor.execute(
                            sql_insert_meta,
                            sql_meta_data
                            )
                    pg_cursor.execute(
                            sql_insert_counts,
                            sql_count_data
                            )
                    pg_conn.commit()
                    #for tag_id in pg_cursor:
                        #print( "inserted tag id: {}".format(tag_id) )
                        #found_tag_id

                    #print( "Final found_tag_id: {}".format( found_tag_id ) )

            except (InfluxDBServerError, InfluxDBClientError, ConnectionError) as e:
                logging.error('Error writing data to Telegraf! Check your database!\n'
                            f'Error: {e}'
                            )

            #try:
            #    client_questdb.row(
            #            'nginx2questdb',
            #            symbols={
            #                #'asn_name': asn_name,
            #                #'distro': str(distro),
            #                #'distro_version': str(distro_version),
            #                #'from_host': log_data_tags['from_host'],
            #                #'http_version': log_data_tags['http_version'],
            #            },
            #            columns={
            #                #'asn': log_data_tags['asn'],
            #                #'ip_type': log_data_tags['ip_type'],
            #                'count': 1,
            #                #'bytes_sent': log_data_fields['bytes_sent'],
            #                #'status_code': log_data_tags['status_code'],
            #            },
            #            #at=timestamp_dt
            #            )
            #    if log_metrics_flush_count > 100:
            #        client_questdb.flush()
            #        log_metrics_flush_count = 0
            #    log_metrics_flush_count = log_metrics_flush_count + 1
            #    #logging.warning(f'Flush count: '+ str( log_metrics_flush_count ) )
            #
            #except IngressError as e:
            #    logging.error('Error writing data to questdb! Check your database!\n'
            #                f'Error: {e}'
            #                )
            log_metrics = []
    else:
        logging.debug(f"Incorrect IP type: {ip_type}")



def processor_proc(
        id,
        squeue,
        logging,
        influxdb_host,
        log_measurement,
        args
        ):
    logging.info( "Process: {} - Started".format( id ) )

    # set up local process connection to things

    client_telegraf = InfluxDBClient(
        host=influxdb_host,
        #port=influxdb_port,
        use_udp=True,
        udp_port=8091,
        )

    asndb = pyasn.pyasn(
            'ribs/ipasn.latest.dat',
            as_names_file='ribs/as_names.latest.json'
            )

    timescale_connection = "host=localhost user=postgres password=einMolHeOkbapdoQuevGotorcyoryucFebsepDoykFiwegBadQualpidabmevNoi dbname=tsdb"

    pg_conn = psycopg2.connect(timescale_connection)
    pg_cursor = pg_conn.cursor()

    num_lines = 0

    while(True):
        line = squeue.get(block=True)
        #print( "{}: {}".format( id, line ) )
        if num_lines >= 2000:
            num_lines = -1
            #logging.info( "{}: Drift goes here".format( id ) )
        if line == "DONE":
            return

        parseline(
                id,
                line,
                client_telegraf,
                pg_conn,
                pg_cursor,
                logging,
                asndb,
                log_measurement,
                args
                )

        num_lines = num_lines + 1
# end processor_proc()

def main():
    global pp
    setproctitle.setproctitle('download-metrics-multi')

    log_level = env.get('GEOIP2INFLUX_LOG_LEVEL', 'info').upper()
    influxdb_host = env.get('INFLUX_HOST', 'localhost')
    log_measurement = env.get('LOG_MEASUREMENT', 'nginx_access_logs')

    # Logging
    logging.basicConfig(
            level=log_level,
            #format='GEOIP2INFLUX %(asctime)s :: %(levelname)s :: %(message)s',
            format='%(levelname)s :: %(message)s',
            datefmt='%d/%b/%Y %H:%M:%S',
            handlers=[
                logging.StreamHandler(),
                #logging.FileHandler(g2i_log_path)
                ]
            )

    logging.info("START")

    logging.info( "re_ipv4_str: "+ re_ipv4_str )
    logging.info( "re_ipv6_str: "+ re_ipv6_str )
    logging.info( "re_log_line_v4_str: "+ re_log_line_v4_str )
    logging.info( "re_log_line_v6_str: "+ re_log_line_v6_str )

    # Argument parsing
    argparser = argparse.ArgumentParser(description='process log entries for database')
    argparser.add_argument(
            '-f',
            '--file',
            action='store',
            nargs=1,
            help='read from file or \'-\' for stdin and exit on completion'
            )
    argparser.add_argument(
            '--date-after',
            action='store',
            nargs=1,
            help='While reading only accept data from after this date'
            )
    argparser.add_argument(
            '--date-before',
            action='store',
            nargs=1,
            help='While reading only accept data from before this date'
            )

    args = argparser.parse_args()
    pp.pprint(args)
    print( args.file )

    if args.date_after is not None:
        try:
            dafter = dateutil.parser.parse(args.date_after[0])
            print( "Dates after: ".format(dafter) )
            pp.pprint( dafter )
        except Exception as e:
            print( e )
            print( "--date-after {} does not parse as a date".format(args.date_after[0]) )
            sys.exit(1)

        try:
            dbefore = dateutil.parser.parse(args.date_before[0])
            print( "Dates after: ".format(dbefore) )
            pp.pprint( dbefore )
        except Exception as e:
            print( e )
            print( "--date-before {} does not parse as a date".format(args.date_before[0]) )
            sys.exit(1)

    # /Argument parsing

    num_processes = 5
    global time_offset_count_limit
    time_offset_count_limit = int( 10000 / num_processes )

    shared_queue = Queue()

    processes = [
            Process(
                target=processor_proc,
                args=(
                    x,
                    shared_queue,
                    logging,
                    influxdb_host,
                    log_measurement,
                    args
                    )
                ) # end of Process definition
            for x in range(num_processes)
            ]

    # start all processes
    for process in processes:
        process.start()

    #tail_type = "seek"
    tail_type = "tail"

    if args.file:
        tail_type = "fileread"

    if tail_type == "seek":
        with open(log_path, 'r', errors='ignore') as log_file:
            logging.info('Starting log parsing')
            str_results = stat(log_path)
            st_size = str_results[6]
            log_file.seek(st_size)
            while True:
                #
                # this is used by the in-built seeking type
                #
                where = log_file.tell()
                line = log_file.readline()
                inodenew = stat(log_path).st_ino
                if inode != inodenew:
                    break
                if not line:
                    #sleep(1)
                    sleep(0.1)
                    log_file.seek(where)
                else:
                    #parseline( line, client_telegraf )
                    shared_queue.put( line )
                #
                # end in-built seeking
                #
    if tail_type == "tail":
        log_file = subprocess.Popen(
                ['tail','-F',log_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
                )
        p = select.poll()
        p.register(log_file.stdout)

        while True:
            try:
                if p.poll(1):
                    #parseline( log_file.stdout.readline(), client_telegraf )
                    shared_queue.put( log_file.stdout.readline() )
                    #print( shared_queue.qsize() )
                else:
                    sleep(0.1)
            except:
                sleep(0.1)

    if tail_type == "fileread":
        lcount=0
        with open(args.file[0], 'r', errors='ignore') if args.file[0] != "-" else sys.stdin as log_file:
            for line in log_file:
                line = line.rstrip()
                shared_queue.put( line )
                #if lcount % 10000 == 0:
                #    print( "{} - {}".format(lcount, line) )
                lcount = lcount + 1
        print("Completed reading file")

    # all processes
    for process in processes:
        print("Terminating process: {}".format(process) )
        process.terminate()
    return

# end main()

if __name__ == '__main__':
    main()
