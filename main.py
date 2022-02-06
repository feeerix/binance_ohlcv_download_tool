from tools import *

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', None)

#
# write_exchangeinfo()

symbol = 'MANAUSD_PERP'

update_db(symbol, 0, 0)