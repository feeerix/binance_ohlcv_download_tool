from tools import *

# initialisation of folder structure
create_folder_structure()
create_api_cfg('api_key', 'api_secret')

# example symbol to download
symbol = 'BTCUSD_PERP'

# function to download OHLCV data
update_db(symbol, 0, 0)
