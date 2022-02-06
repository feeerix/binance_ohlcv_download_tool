import configparser

binance_intervaltable = {
    '1m': 60,
    '5m': 300,
    '15m': 900,
    '30m': 1800,
    '1h': 3600,
    '2h': 7200,
    '4h': 14400,
    '6h': 10800,
    '12h': 43200,
    '1d': 86400,
    '1w': 604800
}

calendar_table = {
    '01': 31,
    '02': 28,
    '03': 31,
    '04': 30,
    '05': 31,
    '06': 30,
    '07': 31,
    '08': 31,
    '09': 30,
    '10': 31,
    '11': 30,
    '12': 31

}

scraper_interval_table = [
    '1m',
    '5m',
    '15m',
    '1h',
    '4h'
]


# BINANCE BASE URLS
binance_inverse_base_url = 'https://dapi.binance.com'
binance_linear_base_url = 'https://fapi.binance.com'
binance_inverse_test_base_url = 'https://testnet.binancefuture.com/'
binance_spot_base_url = 'https://api.binance.com'

# BINANCE WEBSOCKET URLS
binance_inverse_ws_url = 'wss://dstream.binance.com/ws/'
binance_test_inverse_ws_url = 'wss://dstream.binancefuture.com/ws/'
binance_linear_ws_url = 'wss://fstream.binance.com/ws/'

# BINANCE BATCH DOWNLOAD BASE URL
binance_batch_futures_link = 'https://data.binance.vision/data/futures/'

# BINANCE ENDPOINTS

binance_inverse_cont_ep = '/dapi/v1/continuousKlines'
binance_inverse_klines_ep = '/dapi/v1/klines'
binance_inverse_exchange_info_ep = '/dapi/v1/exchangeInfo'

binance_linear_klines_ep = '/fapi/v1/klines'
binance_linear_cont_ep = '/fapi/v1/continuousKlines'
binance_linear_exchange_info_ep = '/fapi/v1/exchangeInfo'

binance_spot_exchange_info_ep = '/api/v3/exchangeInfo'
binance_spot_klines_ep = '/api/v3/klines'

binance_websocket_inverse_listenkey = '/dapi/v1/listenKey'
binance_websocket_linear_listenkey = '/fapi/v1/listenKey'

# API KEYS
"""
You will need to create a file, with the below filename, and add your api key and secret key.
I have included a sample of how they 
"""
cfg_filepath = 'data/api.cfg'
cfg = configparser.ConfigParser()
cfg.read(cfg_filepath)
binance_apikey = cfg.get('binanceauth', 'apikey')
binance_apisecret = cfg.get('binanceauth', 'apisecret')

# MARGIN TYPES
INVERSE = 'INVERSE'
LINEAR = 'LINEAR'
SPOT = 'SPOT'

# DATAFRAME COLUMNS
ohlc_col = ['time', 'open', 'high', 'low', 'close', 'volume']

binance_symbol_info_col = [
    'name',
    'baseCurrency',
    'quoteCurrency',
    'basePrecision',
    'quotePrecision',
    'minTradeQuantity',
    'minTradeAmount',
    'maxTradeQuantity',
    'maxTradeAmount',
    'minPricePrecision',
]

binance_inverse_symbol_info_col = [
    'name',
    'status',
    'base_currency',
    'quote_currency',
    'price_scale',
    'taker_fee',
    'maker_fee',
    'leverage_filter',
    'price_filter',
    'lot_size_filter'
]

# FILEPATHS

binance_data = 'data/'
binance_ohlc_filepath = 'data/ohlc/'
binance_info_filepath = 'data/info/'
binance_batch_dl_filepath = 'data/ohlc/temp/'
binance_ohlc_inverse_filepath = 'data/ohlc/inverse/'
binance_ohlc_linear_filepath = 'data/ohlc/linear/'

binance_folder_structure = [
    binance_data,
    binance_info_filepath,
    binance_ohlc_filepath,
    binance_batch_dl_filepath,
    binance_ohlc_inverse_filepath,
    binance_ohlc_linear_filepath
]

binance_inverse_exchange_info_file = 'data/info/BINANCE_INVERSE_EXCHANGE_INFO.csv'
binance_linear_exchange_info_file = 'data/info/BINANCE_LINEAR_EXCHANGE_INFO.csv'
binance_spot_exchange_info_file = 'data/info/BINANCE_SPOT_EXCHANGE_INFO.csv'

api_file_lines = [
    '[binanceauth]',
    'apikey = ',
    'apisecret = '
]