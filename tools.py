import pandas as pd
import os.path
from os import walk
import os
from urllib.parse import urlencode
from urllib.parse import quote_plus
import urllib3
import json
import requests as req
import hmac
import hashlib
import math
import ast
from constants import *
from datetime import *
import time
import ccxt


"""
LOCAL TOOLS
"""


def currenttime():
    return int(time.time())


def get_margin_type(symbol):
    inverse_exchange_info = pd.read_csv(binance_inverse_exchange_info_file)
    linear_exchange_info = pd.read_csv(binance_linear_exchange_info_file)

    if '.spot' in symbol:
        return SPOT

    elif inverse_exchange_info['symbol'].isin([symbol]).any():
        return INVERSE

    elif linear_exchange_info['symbol'].isin([symbol]).any():
        return LINEAR


"""
DOWNLOAD TOOLS
"""


def link_exists(path):
    """
    Checks if a link exists
    :param path: str
    :return: bool
    """
    r = req.head(path)
    return r.status_code == req.codes.ok


def download_file(url, path, filename):
    """
    Downloads file to the path specified.
    Filename is changed as well.

    :param url: str
    :param path: str
    :param filename: str
    :return: None
    """
    r = req.get(f'{url}{filename}')
    f = open(f'{path}{filename}', 'wb')
    if r.status_code == 200:
        for chunk in r.iter_content(1024):
            f.write(chunk)
    f.close()


def get_checksum(filename, hash_function):
    """Generate checksum for file baed on hash function (MD5 or SHA256).

    Args:
        filename (str): Path to file that will have the checksum generated.
        hash_function (str):  Hash function name - supports MD5 or SHA256

    Returns:
        str`: Checksum based on Hash function of choice.

    Raises:
        Exception: Invalid hash function is entered.

    """
    hash_function = hash_function.lower()
    with open(filename, "rb") as f:
        bytes_data = f.read()  # read file as bytes
        if hash_function == "md5":
            readable_hash = hashlib.md5(bytes_data).hexdigest()
        elif hash_function == "sha256":
            readable_hash = hashlib.sha256(bytes_data).hexdigest()
        else:
            print("Invalid hash function. Please Enter MD5 or SHA256")

    return readable_hash


def unzip_file(filepath, dest_dir):
    file_msg = filepath.split('/')[-1]
    with ZipFile(filepath, 'r') as zf:
        zf.extractall(
            path=dest_dir
        )
        print(f'Unzipped: {file_msg}')


def compare_checksum(file, checksum):
    """
    Compares checksum to file, making sure it is the correct file.
    Currently set to SHA256

    :return: bool
    """
    f = open(checksum, "r")
    if f.read().split(' ')[0] == get_checksum(file, 'SHA256'):
        return True
    else:
        return False


def clean_ohlc(filepath):
    """
    Filename to be parsed from filepath, and subsequently data scrubbed
    - Time column to be changed to int
    - Find repeat time data
    - Find gaps in data (time gaps)

    :param filepath: file PATH of the file - not file name
    :return: None
    """
    filename = filepath.split('/')[-1]
    parsefilename = filename.split('.')[0].split('_')
    del parsefilename[-1]
    if 'PERP' in parsefilename:
        parsefilename.remove('PERP')
        parsefilename[1] = f'{parsefilename[1]}_PERP'
    data = pd.read_csv(filepath)
    data.drop_duplicates('time', inplace=True, ignore_index=True)
    data['time'] = data.apply(lambda x: x['time']/1000 if x['time'] > 9999999999 else x['time'], axis=1)
    data['time'] = data.apply(lambda x: int(x['time']), axis=1)
    data.to_csv(filepath, index=False)
    print('Completed cleanse!')


def clean_ohlcv_csv(file):
    data = pd.read_csv(file,
                       header=None,
                       names=ohlc_col,
                       usecols=[0, 1, 2, 3, 4, 5]
                       )
    data['time'] = data['time'].div(1000)
    data['time'] = data.apply(lambda x: int(x['time']), axis=1)
    return data


def list_of_files(folder_path):
    return next(
        walk(folder_path), (None, None, [])
    )[2]  # [] if no file


def check_create_fp(filepath):
    # Debug Print
    print(f"Checking filepath ({filepath})")

    if not os.path.isdir(filepath):  # If does not exist
        os.mkdir(filepath)  # Create filepath
        print(f'Created filepath')
    else:  # If the filepath does exist
        pass
        # print(f'Filepath already exists!')


def check_fp(filepath):
    if os.path.isdir(filepath):
        return True
    else:
        return False


def check_fn(filename):
    if os.path.isfile(filename):
        return True
    else:
        return False


def convert_unix_interval_to_str(interval):
    for val in binance_intervaltable.keys():
        if binance_intervaltable[val] == interval:
            return val


def convert_str_interval_to_unix(interval):
    """
    :param interval: String of interval ex: '15m'
    :type interval: str
    :return: int
    """
    return binance_intervaltable[interval]


"""
DATE TOOLS
"""


def get_last_closed_time(unixinterval):
    return (int(time.time() - unixinterval) // unixinterval) * unixinterval


def round_nearest(x, a):
    return round(x / a) * a


def round_down(x, a):
    return math.floor(x / a) * a


def leapyr(n):
    if n % 400 == 0:
        return True
    if n % 100 == 0:
        return False
    if n % 4 == 0:
        return True
    return False


def convert_timecode_to_readable(timecode):
    """
    :param timecode: UTC timecode
    :return: %Y-%m-%d %H:%M:%S
    """
    return datetime.utcfromtimestamp(timecode).strftime('%Y-%m-%d %H:%M:%S')


def convert_readable_date_to_timecode(readable):
    """
    :param readable: %Y-%m-%d
    :return: UTC timecode
    """
    # ASSUME TIME MIDNIGHT
    return int(
        datetime.strptime(
            readable,
            "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        ).timestamp()
    )


def convert_readable_datetime_to_timecode(time_and_date, **kwargs):
    """
    :param time_and_date: 2021-08-12 23:59
    :return: default unit in seconds
    """
    if 'unit' not in kwargs:
        return int(
            datetime.strptime(
                time_and_date,
                "%Y-%m-%d %H:%M").replace(
                tzinfo=timezone.utc
            ).timestamp()
        )
    else:
        if kwargs['unit'] == 'ms':
            return int(
                datetime.strptime(
                    time_and_date,
                    "%Y-%m-%d %H:%M").replace(
                    tzinfo=timezone.utc
                ).timestamp()
            ) * 1000


def convert_readable_datetime_seconds_to_timecode(time_and_date):
    """
    :param time_and_date: 2021-08-12 23:59:00
    :return:
    """
    return int(
        datetime.strptime(
            time_and_date,
            "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        ).timestamp()
    )


def get_time_from_timecode(timecode):
    """
    :param timecode: UTC timecode
    :return: %H:%M:%S
    """
    return datetime.utcfromtimestamp(timecode).strftime('%H:%M:%S')


def get_date_from_timecode(timecode):
    readable = convert_timecode_to_readable(timecode)
    return readable.split(' ')[0].split('-')[2]


def get_month_from_timecode(timecode):
    readable = convert_timecode_to_readable(timecode)
    return readable.split(' ')[0].split('-')[1]


def get_year_from_timecode(timecode):
    readable = convert_timecode_to_readable(timecode)
    return readable.split(' ')[0].split('-')[0]


def month_iterate(month):
    if int(month) < 9:
        return f'0{(int(month) + 1)}'
    elif int(month) == 12:
        return '01'
    else:
        return str(int(month) + 1)


def currentdate():
    return convert_timecode_to_readable(currenttime()).split(' ')[0]


def yesterday():
    return convert_timecode_to_readable(currenttime() - 86400).split(' ')[0]


def lastdate(the_date):
    # 2021-08-12 23:59:00
    day = the_date.split('-')[2]
    month = the_date.split('-')[1]
    year = the_date.split('-')[0]
    if month == '01' and day == '01':
        # GO TO END OF YEAR
        year = int(year) - 1
        month = '12'
        day = '31'
    elif day == '01' and \
            leapyr(int(year)) and month == '03':
        # LEAP YEAR FEB
        day = '29'
        month = '02'
    elif day == '01' and leapyr(int(year)) is False:
        if int(month) > 10:
            month = str(int(month) + 1)
        else:
            month = f'0{int(month) - 1}'
        # END OF MONTH
        day = str(calendar_table[month])
    elif int(day) > 10:
        day = int(day) - 1
    else:
        day = f'0{int(day) - 1}'
    return f'{year}-{month}-{day}'


def lastmonth(month):
    if int(month) > 10:
        return str(int(month) - 1)
    elif month == '01':
        return '12'
    else:
        return f'0{int(month) - 1}'


def last_month_first(the_date):
    month = the_date.split('-')[1]
    year = the_date.split('-')[0]
    if int(month) > 10:
        month = str(int(month) - 1)
    elif month == '01':
        month = '12'
        year = str(int(year) - 1)
    else:
        month = f'0{int(month) - 1}'
    return f'{year}-{month}-01'


def last_year(the_date):
    return f"{int(the_date.split('-')[0]) - 1}-{the_date.split('-')[1]}-{the_date.split('-')[2]}"


def nextmonth(month):
    if int(month) < 9:
        return f'0{int(month) + 1}'
    elif month == '12':
        return '01'
    else:
        return str(int(month) + 1)


def next_month_full(the_date):
    month = the_date.split('-')[1]
    year = the_date.split('-')[0]
    if int(month) < 9:
        month = f'0{int(month) + 1}'
    elif month == '12':
        month = '01'
        year = str(int(year) + 1)
    else:
        month = str(int(month) + 1)
    return f'{year}-{month}-xx'


def next_month_first(the_date):
    month = the_date.split('-')[1]
    year = the_date.split('-')[0]
    if int(month) < 9:
        month = f'0{int(month) + 1}'
    elif month == '12':
        month = '01'
        year = str(int(year) + 1)
    else:
        month = str(int(month) + 1)
    return f'{year}-{month}-01'


def nextdate(the_date):
    # 2021-08-12 23:59:00
    day = the_date.split('-')[2]
    month = the_date.split('-')[1]
    year = the_date.split('-')[0]
    if month == '12' and day == '31':
        # END OF YEAR
        year = int(year) + 1
        month = '01'
        day = '01'
    elif day == str(calendar_table[month] + 1) and \
            leapyr(int(year)) and month == '02':
        # LEAP YEAR FEB
        month = '03'
        day = '01'
    elif day == str(calendar_table[month]) and leapyr(int(year)) is False:
        if int(month) < 9:
            month = f'0{int(month) + 1}'
        else:
            month = str(int(month) + 1)
        # END OF MONTH
        day = '01'
    elif int(day) < 9:
        # +1 WITH ZERO ADDED
        day = f'0{int(day) + 1}'
    else:
        # ALL OTHER TIMES
        day = int(day) + 1
    return f'{year}-{month}-{day}'


"""
REST API TOOLS
"""


def hashing(query_string):
    # Hashing function
    return hmac.new(binance_apisecret.encode('utf-8'), query_string.encode('utf-8'), hashlib.sha256).hexdigest()


def dispatch_request(http_method):
    session = req.Session()
    session.headers.update({
        'Content-Type': 'application/json;charset=utf-8',
        'X-MBX-APIKEY': binance_apikey
    })
    return {
        'GET': session.get,
        'DELETE': session.delete,
        'PUT': session.put,
        'POST': session.post,
    }.get(http_method, 'GET')


# noinspection PyTypeChecker
def send_signed_request(http_method, url_path, base_url, payload=None):
    if payload is None:
        payload = {}

    # Encode to be in URL
    query_string = urlencode(payload)

    # Timestamp
    if query_string:
        query_string = "{}&timestamp={}".format(query_string, servertime())
    else:
        query_string = 'timestamp={}'.format(servertime())

    # url = cm_base_url + url_path + '?' + query_string + '&signature=' + hashing(query_string)
    url = base_url + url_path + '?' + query_string + '&signature=' + hashing(query_string)

    print("{} {}".format(http_method, url))
    params = {'url': url, 'params': {}}
    response = dispatch_request(http_method)(**params)
    return response.json()


# noinspection PyTypeChecker
def send_public_request(url_path, base_url, payload=None):
    if payload is None:
        payload = {}
    query_string = urlencode(payload, True)
    url = base_url + url_path
    if query_string:
        url = url + '?' + query_string
    print("{}".format(url))
    response = dispatch_request('GET')(url=url)
    return response.json()


def servertime():
    return int(req.get(binance_inverse_base_url + '/dapi/v1/time').json()['serverTime'] / 1000) * 1000


def write_exchangeinfo(mode=None):
    """
    Function to write specific exchange information
    :param mode: int
    :return: None
    """
    if mode is None:
        for x in range(3):
            get_exchange_info(x)

    else:
        get_exchange_info(mode)


def get_exchange_info(mode):
    """
    :param mode: int
    :return: None
    """
    # Variable Definition
    endpoint = None
    base_url = None
    filepath = None

    if mode == 0:  # LINEAR
        endpoint = binance_linear_exchange_info_ep
        base_url = binance_linear_base_url
        mode = 'linear'
        filepath = binance_linear_exchange_info_file

    elif mode == 1:  # INVERSE
        endpoint = binance_inverse_exchange_info_ep
        base_url = binance_inverse_base_url
        mode = 'inverse'
        filepath = binance_inverse_exchange_info_file

    elif mode == 2:  # SPOT
        endpoint = binance_spot_exchange_info_ep
        base_url = binance_spot_base_url
        mode = 'spot'
        filepath = binance_spot_exchange_info_file

    # Send Request
    exchangeinfo = send_public_request(
        endpoint,
        base_url
    )

    df = pd.DataFrame(exchangeinfo['symbols'])
    df.to_csv(filepath)

    print(f'Updated and saved Binance {mode} exchange info to CSV.')


def get_klines(symbol, interval, **kwargs):

    # Endpoint and URL declaration
    kline_ep = None
    base_url = None

    # Result dataframe
    res = pd.DataFrame(columns=ohlc_col)

    # Parameters
    params = {
        'symbol': symbol,
        'interval': interval
    }

    # Adding start time and end time to parameters
    if 'starttime' in kwargs:
        params['startTime'] = int(int(kwargs['starttime']) * 1000)
    if 'limit' in kwargs:
        params['limit'] = kwargs['limit']
    if 'endtime' in kwargs:
        params['endTime'] = int(int(kwargs['endtime']) * 1000)

    # Changing endpoint depending on margin type
    if get_margin_type(symbol) == INVERSE:
        kline_ep = binance_inverse_klines_ep
        base_url = binance_inverse_base_url
    elif get_margin_type(symbol) == LINEAR:
        kline_ep = binance_linear_klines_ep
        base_url = binance_linear_base_url
    elif get_margin_type(symbol) == SPOT:
        kline_ep = binance_spot_klines_ep
        base_url = binance_spot_base_url

    # Sending request
    result = send_public_request(
        kline_ep,
        base_url,
        params
    )

    # Creation of kline dataframe
    for klines in result:
        kline = dict()
        kline['time'] = int(klines[0] / 1000)
        kline['open'] = klines[1]
        kline['high'] = klines[2]
        kline['low'] = klines[3]
        kline['close'] = klines[4]
        kline['volume'] = klines[5]
        res = res.append(kline, ignore_index=True)

    return res


def batch_binance_downloader(symbol, interval, batch_type, **kwargs):
    """
    This function downloads each individual batch depending on the scale of download required.
    That is, it can download klines from that day (through REST API requests) or download them from
    data.binance.vision/ and unzip them accordingly.
    """
    # Variable definition
    margin_type = get_margin_type(symbol)
    unix_interval = convert_str_interval_to_unix(interval)
    filename = None

    if batch_type != 'intraday':  # Monthly or Daily
        link_path = 'https://data.binance.vision/data/futures/'

        # String for download link, INVERSE / LINEAR
        if margin_type == INVERSE:
            link_path += 'cm/'
        elif margin_type == LINEAR:
            link_path += 'um/'

        # Update link path
        link_path += batch_type + f'/klines/{symbol}/{interval}/'

        # Start construction of filename
        month = get_month_from_timecode(kwargs['starttime'])
        year = get_year_from_timecode(kwargs['starttime'])
        if batch_type == 'daily':
            the_date = get_date_from_timecode(kwargs['starttime'])

            # Filename construction
            filename = f"{symbol}-{interval}-{year}-{month}-{the_date}.zip"
        elif batch_type == 'monthly':

            # Filename construction
            filename = f"{symbol}-{interval}-{year}-{month}.zip"

        print(f"Downloading from: {link_path + filename}")
        if link_exists(f'{link_path}{filename}'):  # If the file does not exist
            temp_path = f"{binance_ohlc_filepath}temp/"
            download_path = f"{binance_ohlc_filepath}{symbol}/{interval}/"
            print(f"Downloading to: {download_path}")

            # Download File
            if link_exists(f'{link_path}{filename}'):
                download_file(link_path, temp_path, filename)
                print(f'Download Success! // {filename}')
            else:
                print('---- ERROR ----')
                print('Download Unsuccessful! - OHLC file does not seem to exist!')
                print(f"Filename: {filename}")

            # Download Checksum
            if link_exists(f'{link_path}{filename}.CHECKSUM'):
                download_file(link_path, temp_path, f'{filename}.CHECKSUM')
                print(f'Download Success! // {filename}.CHECKSUM')
            else:
                print('---- ERROR ----')
                print('Download Unsuccessful! - Checksum does not seem to exist!')
                print(f"Filename: {filename}")

            # If checksum computes - unzip file
            if compare_checksum(temp_path + filename, temp_path + filename + '.CHECKSUM'):
                unzip_file(temp_path + filename, temp_path)
            else:  # Otherwise, give error message
                print(f'The checksum does not seem to be right for filename: {filename}')
                return pd.DataFrame()

            # Create sanitised file
            ret_file = clean_ohlcv_csv(temp_path + filename)

            # Remove temp files
            for files in list_of_files(temp_path):
                os.remove(f"{temp_path}{files}")
                print(f'Removed file: {temp_path}{files}')

            return ret_file
        else:
            print('---- ERROR ----')
            print('Download Unsuccessful! - OHLC file does not seem to exist!')
            print(f"Filename: {filename}")

            print('Adjusting to intraday')
            batch_type = 'intraday'

    # Batch type tells us how large of a batch we are downloading, monthly, daily or intraday
    else:
        """
        Create db via REST API to be attached accordingly
        endtime is REQUIRED
        """
        # Return dataframe defined
        ret_file = pd.DataFrame(columns=ohlc_col)

        # Adjusting datatypes
        start_time = int(kwargs['starttime'])
        end_time = int(kwargs['endtime'])

        # The kline grab loop
        while True:
            # Checking whether the distance to end_time is within limit
            distance = int((end_time - start_time) / unix_interval)

            # Some limit to distance
            if distance < 500:
                next_start = end_time - unix_interval
                limit = distance
            # Max distance
            else:
                limit = 500
                next_start = start_time + (limit * unix_interval)

            if limit == 0:
                break

            new_data = get_klines(
                symbol,
                interval,
                starttime=start_time,
                endtime=end_time,
                limit=limit
            )

            # Append data to existing dataframe
            ret_file = ret_file.append(
                new_data,
                ignore_index=True
            )

            # Check if we are at end_time
            if next_start == end_time - unix_interval:

                # Break loop to return data
                break

            else:

                # Update start time to next one.
                start_time = next_start

            """
            Sleeping to prevent ban from server. Current Binance default for /api/ method is:
            1200/min limit based on IP

            Sleep for 0.05 means Approximately 20 requests per second, which is on the limit based on the above
            limit, therefore limited to 0.06 seconds which is 16.6 requests per second
            """
            time.sleep(0.06)
        # Function to return data
        return ret_file