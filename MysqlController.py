import json
import warnings
import pymysql


warnings.filterwarnings("ignore")

class MysqlController():

    def __init__(self):

        self.loadMysqlConfig()
        self.loadMysqlPayload()

    # log file to Mysql
    def coreProcessor(self, pathLog, fileLog, paramLog):
        
        self._pathLog = pathLog
        self._fileLog = fileLog
        self._paramLog = paramLog

        with open('../config.ini')as config_f:
            config = json.load(config_f)

        self._whiteHosts = config.get('whiteHosts')

        '''
        dataDict = {
            'path':[
                ('host','path')],
            'file':[
                ('host','file')],
            'param':[
                ('host','param')]}
        '''
        dataDict = {
            'path':self.getDataFromLog(self._pathLog),
            'file':self.getDataFromLog(self._fileLog),
            'param':self.getDataFromLog(self._paramLog)}

        self.dataStorage(dataDict)

    def loadMysqlConfig(self):

        with open('../config.ini') as config_f:
            j = json.load(config_f)
            mysql_config = j.get('mysql')
            # options = j.get('options')
            
        self._host = mysql_config.get('host')
        self._user = mysql_config.get('user')
        self._password = mysql_config.get('password')
        self._port = int(mysql_config.get('port'))
        self._database = mysql_config.get('database')

        # self._path_max_length = int(options.get('pathMaxLength'))
        # self._file_max_length = int(options.get('fileMaxLength'))

    def loadMysqlPayload(self):

        self._createDatabase = '''
            create database if not exists {} charset utf8;
            '''.format(self._database)

        self._createTableParam = '''
            create table if not exists param(
            id int not null primary key auto_increment,
            host varchar(100),
            param varchar(300) not null,
            count int default 1);
            '''
        self._createTablepath = '''
            create table if not exists path(
            id int not null primary key auto_increment,
            host varchar(100),
            path varchar(300) not null,
            count int default 1);
            '''
        self._createTableFile = '''
            create table if not exists file(
            id int not null primary key auto_increment,
            host varchar(100),
            file varchar(300) not null,
            count int default 1);
            '''
        self._selectTableParam = '''
            select count(*) from param where
            host = %s and param = %s
            '''
        self._selectTablepath = '''
            select count(*) from path where
            host = %s and path = %s
            '''
        self._selectTableFile = '''
            select count(*) from file where
            host = %s and file = %s
            '''
        self._insertTableParam = '''
            insert into param(
            host,param) values(%s,%s)
            '''
        self._insertTablepath = '''
            insert into path(
            host,path) values(%s,%s)
            '''
        self._insertTableFile = '''
            insert into file(
            host,file) values(%s,%s)
            '''
        self._updateTableParamCount = '''
            update param set count = count + 1
            where host = %s and param = %s
            '''
        self._updateTablepathCount = '''
            update path set count = count + 1
            where host = %s and path = %s
            '''
        self._updateTableFileCount = '''
            update file set count = count + 1
            where host = %s and file = %s
            '''

    # testing mysql connections
    def connectTest(self):

        try:
            connection = pymysql.connect(host=self._host,
                user=self._user,
                password=self._password,
                port=self._port,
                cursorclass=pymysql.cursors.DictCursor)
            print('\n'+'='*10)
            print('MySQL Connection Succession')
            print('='*10+'\n')

        except Exception as e:

            if e[0] == 1045:
                print('MySQL Access denied !!')
        else:

            cursor = connection.cursor()

            cursor.execute(self._createDatabase)
            connection.commit()

            connection.select_db(self._database)
            cursor.execute(self._createTableParam)
            cursor.execute(self._createTablepath)
            cursor.execute(self._createTableFile)
            connection.commit()

            connection.close()

            return True

    # @return [(host,orther),]
    def getDataFromLog(self, logFile):

        tempData = set()

        with open(logFile)as log_f:

            for line in log_f:
                line = line.strip()
                
                host,orther = line.split('\t',1)

                if orther.strip() == '':
                    continue

                # The host that is not on the whitelist will be reset to empty
                for whiteHost in self._whiteHosts:
                    if host.endswith(whiteHost):
                        host = '*.{}'.format(whiteHost)
                        break
                else:
                    host = ''

                tempData.add((host, orther))

        return tempData

    '''
    dataDict = {
        'path':[
            ('host','path')],
        'file':[
            ('host','file')],
        'param':[
            ('host','param')]}
    '''
    def dataStorage(self, dataDict):

        try:
            connection = pymysql.connect(host=self._host,
                user=self._user,
                password=self._password,
                port=self._port,
                db=self._database,
                cursorclass=pymysql.cursors.DictCursor)

        except Exception as e:

            if e[0] == 1045:
                print('MySQL Access denied !!')                
        else:

            cursor = connection.cursor()

            if dataDict.get('path'):
                for host, path in dataDict.get('path'):
                    self.operateTablepath(cursor, host, path)
                connection.commit()

            if dataDict.get('file'):
                for host, file in dataDict.get('file'):
                    self.operateTableFile(cursor, host, file)
                connection.commit()

            if dataDict.get('param'):
                paramSet = set()
                for host,params in dataDict.get('param'):
                    for param in params.split(','):
                        if param not in paramSet:
                            paramSet.add(param)
                            self.operateTableParam(cursor, host, param)
                connection.commit()

        finally:
            connection.close()

    def operateTableParam(self, cursor, host, param):
        
        cursor.execute(self._selectTableParam, (host, param))
        itemCount = cursor.fetchone()

        if not itemCount.get('count(*)'):
            cursor.execute(self._insertTableParam, (host, param))
        else:
            cursor.execute(self._updateTableParamCount, (host, param))

    def operateTablepath(self, cursor, host, path):
        
        cursor.execute(self._selectTablepath, (host, path))
        itemCount = cursor.fetchone()

        if not itemCount.get('count(*)'):
            cursor.execute(self._insertTablepath, (host, path))
        else:
            cursor.execute(self._updateTablepathCount, (host, path))

    def operateTableFile(self, cursor, host, file):
        
        cursor.execute(self._selectTableFile, (host, file))
        itemCount = cursor.fetchone()

        if not itemCount.get('count(*)'):
            cursor.execute(self._insertTableFile, (host, file))
        else:
            cursor.execute(self._updateTableFileCount, (host, file))
