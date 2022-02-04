from tools import *

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', None)

symbol = 'BTCUSD_PERP'
interval = '15m'

update_binance_db()