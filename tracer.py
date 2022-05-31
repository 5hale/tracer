# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import binascii
import codecs
import os
import platform
import re
import subprocess
import threading
import time
import datetime         # 수정됨 : 추가
import chardet          # 수정됨 : 추가
import sys
import json             # 수정됨 : 추가

import frida


def main():
    from colorama import Fore, Style
    import json

    from frida_tools.application import ConsoleApplication, input_with_cancellable

    class TracerApplication(ConsoleApplication, UI):
        def __init__(self):
            super(TracerApplication, self).__init__(self._await_ctrl_c)
            self._palette = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.GREEN, Fore.RED, Fore.BLUE]
            self._next_color = 0
            self._attributes_by_thread_id = {}
            self._last_event_tid = -1

        def _add_options(self, parser):
            pb = TracerProfileBuilder()
            parser.add_argument("-I", "--include-module", help="include MODULE", metavar="MODULE", type=pb.include_modules)
            parser.add_argument("-X", "--exclude-module", help="exclude MODULE", metavar="MODULE", type=pb.exclude_modules)
            parser.add_argument("-i", "--include", help="include [MODULE!]FUNCTION", metavar="FUNCTION", type=pb.include)
            parser.add_argument("-x", "--exclude", help="exclude [MODULE!]FUNCTION", metavar="FUNCTION", type=pb.exclude)
            parser.add_argument("-a", "--add", help="add MODULE!OFFSET", metavar="MODULE!OFFSET", type=pb.include_relative_address)
            parser.add_argument("-T", "--include-imports", help="include program's imports", type=pb.include_imports)
            parser.add_argument("-t", "--include-module-imports", help="include MODULE imports", metavar="MODULE", type=pb.include_imports)
            parser.add_argument("-m", "--include-objc-method", help="include OBJC_METHOD", metavar="OBJC_METHOD", type=pb.include_objc_method)
            parser.add_argument("-M", "--exclude-objc-method", help="exclude OBJC_METHOD", metavar="OBJC_METHOD", type=pb.exclude_objc_method)
            parser.add_argument("-j", "--include-java-method", help="include JAVA_METHOD", metavar="JAVA_METHOD", type=pb.include_java_method)
            parser.add_argument("-J", "--exclude-java-method", help="exclude JAVA_METHOD", metavar="JAVA_METHOD", type=pb.exclude_java_method)
            parser.add_argument("-s", "--include-debug-symbol", help="include DEBUG_SYMBOL", metavar="DEBUG_SYMBOL", type=pb.include_debug_symbol)
            parser.add_argument("-q", "--quiet", help="do not format output messages", action='store_true', default=False)
            parser.add_argument("-d", "--decorate", help="add module name to generated onEnter log statement", action='store_true', default=False)
            parser.add_argument("-S", "--init-session", help="path to JavaScript file used to initialize the session", metavar="PATH", action='append', default=[])
            parser.add_argument("-P", "--parameters", help="parameters as JSON, exposed as a global named 'parameters'", metavar="PARAMETERS_JSON")
            parser.add_argument("-o", "--output", help="dump messages to file", metavar="OUTPUT")
            # 수정됨 : --find-string 옵션 추가, 입력된 문자열을 검색함
            parser.add_argument("--find-string", help="Search String", metavar="String regex",type=pb.find_string)
            # 수정됨 : --find-hex 옵션 추가, 입력된 헥스값을 검색함
            parser.add_argument("--find-hex", help="Search hex", metavar="hex regex",type=pb.find_hex)
            # 수정됨 : --set-encoding 옵션 추가, 입력된 encoding으로 검색된 값을 decoding 함
            parser.add_argument("--set-encoding", help="Set Encoding", metavar="Encoding",type=pb.set_encoding)
            # 수정됨 : -A 옵션 추가, 모든 로그 저장하는 방식 활성화
            parser.add_argument("-A", "--all-logs", help="Log All Payload", action='store_true', default=False)            
            # 수정됨 : -C 옵션 추가, 찾은 문자열 및 헥스 값 콘솔출력 여부
            parser.add_argument("-C", "--print-console", help="Print on Console", action='store_true', default=False)
            # 수정됨 : --json 옵션 추가, 양식에 맞는 JSON 파일을 통해 사용자 함수 후킹 시도
            parser.add_argument("--json", help="User function hooking as JSON", metavar="json_file::[start_addr::end_addr::hook_count::start_index::section]",type=pb.include_relative_address_json)
            self._profile_builder = pb           

        def _usage(self):
            return "%(prog)s [options] target"

        def _initialize(self, parser, options, args):
            self._tracer = None
            self._profile = self._profile_builder.build()
            self._profile.allLogs=options.all_logs
            self._profile.printConsole=options.print_console           
            self._quiet = options.quiet
            self._decorate = options.decorate
            self._output = None
            self._output_path = options.output
            
            self._init_scripts = []
            for path in options.init_session:
                with codecs.open(path, 'rb', 'utf-8') as f:
                    source = f.read()
                self._init_scripts.append(InitScript(path, source))

            if options.parameters is not None:
                try:
                    params = json.loads(options.parameters)
                except Exception as e:
                    raise ValueError("failed to parse parameters argument as JSON: {}".format(e))
                if not isinstance(params, dict):
                    raise ValueError("failed to parse parameters argument as JSON: not an object")
                self._parameters = params
            else:
                self._parameters = {}

        def _needs_target(self):
            return True

        def _start(self):
            if self._output_path is not None:
                self._output = OutputFile(self._output_path)

            stage = 'early' if self._target[0] == 'file' else 'late'
            self._tracer = Tracer(self._reactor, FileRepository(self._reactor, self._decorate), self._profile,
                    self._init_scripts, log_handler=self._log)
            # 수정됨
            print(type(self._tracer))
            try:
                self._tracer.start_trace(self._session, stage, self._parameters, self._runtime, self)
            except Exception as e:
                self._update_status("Failed to start tracing: {error}".format(error=e))
                self._exit(1)

        def _stop(self):
            self._tracer.stop()
            self._tracer = None
            if self._output is not None:
                self._output.close()
            self._output = None

        def _await_ctrl_c(self, reactor):
            while True:
                try:
                    input_with_cancellable(reactor.ui_cancellable)
                except frida.OperationCancelledError:
                    break
                except KeyboardInterrupt:
                    break

        def on_trace_progress(self, status, *params):
            if status == 'initializing':
                self._update_status("Instrumenting...")
            elif status == 'initialized':
                self._resume()
            elif status == 'started':
                (count,) = params
                if count == 1:
                    plural = ""
                else:
                    plural = "s"
                self._update_status("Started tracing %d function%s. Press Ctrl+C to stop." % (count, plural))

        def on_trace_warning(self, message):
            self._print(Fore.RED + Style.BRIGHT + "Warning" + Style.RESET_ALL + ": " + message)

        def on_trace_error(self, message):
            self._print(Fore.RED + Style.BRIGHT + "Error" + Style.RESET_ALL + ": " + message)
            self._exit(1)

        def on_trace_events(self, events):
            no_attributes = Style.RESET_ALL
            for timestamp, thread_id, depth, message in events:
                if self._output is not None:
                    self._output.append(message + "\n")
                elif self._quiet:
                    self._print(message)
                else:
                    indent = depth * "   | "
                    attributes = self._get_attributes(thread_id)
                    if thread_id != self._last_event_tid:
                        self._print("%s           /* TID 0x%x */%s" % (attributes, thread_id, Style.RESET_ALL))
                        self._last_event_tid = thread_id
                    self._print("%6d ms  %s%s%s%s" % (timestamp, attributes, indent, message, no_attributes))

        def on_trace_handler_create(self, target, handler, source):
            if self._quiet:
                return
            self._print("%s: Auto-generated handler at \"%s\"" % (target, source.replace("\\", "\\\\")))

        def on_trace_handler_load(self, target, handler, source):
            if self._quiet:
                return
            self._print("%s: Loaded handler at \"%s\"" % (target, source.replace("\\", "\\\\")))

        def _get_attributes(self, thread_id):
            attributes = self._attributes_by_thread_id.get(thread_id, None)
            if attributes is None:
                color = self._next_color
                self._next_color += 1
                attributes = self._palette[color % len(self._palette)]
                if (1 + int(color / len(self._palette))) % 2 == 0:
                    attributes += Style.BRIGHT
                self._attributes_by_thread_id[thread_id] = attributes
            return attributes

    app = TracerApplication()
    app.run()


class TracerProfileBuilder(object):
    def __init__(self):
        self._spec = []
        self._findString = []                     # 수정됨 : 검색할 문자열 리스트
        self._findHex = []                        # 수정됨 : 검색할 헥스 리스트
        self._setEncoding=""                      # 수정됨 : 사용자 지정 인코딩

    def find_string(self, *find_string_globs):    # 수정됨 :  옵션에서 입력한 변수 리스트에 추가
        for fs in find_string_globs:
            self._findString.append(fs)            
        return self

    def find_hex(self, *find_hex_globs):          # 수정됨 :  옵션에서 입력한 변수 리스트에 추가
        for fh in find_hex_globs:
            self._findHex.append(fh)            
        return self

    def set_encoding(self, *set_encoding_globs):      # 수정됨 :  사용자 인코딩값 입력
        for se in set_encoding_globs:
            self._setEncoding = se
        return self

    # 수정됨 : --json 옵션 처리
    def include_relative_address_json(self, *address_rel_offsets):
        # 사용자 입력값 받을 리스트
        json_arg =[]
        # 사용자 입력값 args에 리스트 형식으로 저장
        args = address_rel_offsets[0].split('::')
        # 사용자 입력값 길이
        args_len = len(args)
        # 사용자 입력값 만큼 json_arg에 저장
        for i in range(0,args_len) : json_arg.append(args[i])
        # 입력되지 않은 부분 None으로 채움
        if(args_len < 6): 
            for i in range(0,6-args_len): json_arg.append(None)

        # 입력되지 않은 부분 초기값으로 세팅
        # json_file::[start_addr::end_addr::hook_count::start_index::section]
        file_path = json_arg[0]
        if(json_arg[1] in (None,""," ")): start_addr = None
        else : start_addr = json_arg[1]
        if(json_arg[2] in (None,""," ")): end_addr = None
        else : end_addr = json_arg[2]
        if(json_arg[3] in (None,""," ")): hook_count = 2000
        else : hook_count = int(json_arg[3])
        if(json_arg[4] in (None,""," " )): start_index = 0
        else : start_index = int(json_arg[4])
        if(json_arg[5] in (None,""," ")): section = "text"
        else : section = json_arg[5]

        # JSON 파일 불러옴
        with open(file_path) as f:
            data = json.load(f)
            #print("=================================")

            # JSON 데이터 처리
            for i,key in enumerate(data) :
                # section이 입력되었을경우 해당 섹션의 JSON 데이터를 불러옴, default는 "text"
                if(section in key):
                    # start_addr가 입력되고 end_addr가 입력되지 않은 경우
                    if(start_addr!=None and end_addr==None):
                        for j, attr in enumerate(data[key]):                        # attr = data[key][j]
                            # 함수의 Address(offset)가 입력된 start_addr와 일치할 경우 
                            # start_index을 해당 start_addr의 위치값을 후킹 시작 위치로 설정
                            if(attr['Address']==start_addr): start_index = j
                    # start_addr,end_addr가 입력된 있는 경우
                    elif(start_addr!=None and end_addr!=None):
                        for k, attr in enumerate(data[key]): 
                            # 입력된 start_addr와 end_addr의 위치를 각각 후킹 시작, 후킹 마지막 위치로 설정
                            if(attr['Address']==start_addr): start_index = k
                            if(attr['Address']==end_addr): hook_count = k-start_index+1

                    # start_index를 기점으로 후킹 데이터 전달, default는 0
                    # hook_count는 start_addr와 end_addr의 위치 차이를 우선으로함
                    # end_addr이 없을 경우 hook_count는 사용자의 입력값을 우선으로함
                    # hook_count는 2000을 넘기지 않음
                    for l in range(start_index,start_index + hook_count): 
                        # 후킹 데이터가 2000개가 넘을 경우 break
                        if(l - start_addr > 2000):break
                        # 후킹 데이터 생성 후 -a 옵션의 파라미터로 보냄
                        #try: print(str(l)+"  "+data['Module']+"!"+data[key][l]['Address'])
                        try: 
                            f = data['Module']+"!"+data[key][l]['Address']
                            self._spec.append(('include', 'relative-function', f))
                        except Exception as e: break

            #print("=================================")              
            #print("total : "+str(hook_count))
        return self

    def include_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('include', 'module', m))
        return self

    def exclude_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('exclude', 'module', m))
        return self

    def include(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('include', 'function', f))
        return self

    def exclude(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('exclude', 'function', f))
        return self

    def include_relative_address(self, *address_rel_offsets):
        for f in address_rel_offsets:
            self._spec.append(('include', 'relative-function', f))
        return self

    def include_imports(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('include', 'imports', m))
        return self

    def include_objc_method(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('include', 'objc-method', f))
        return self

    def exclude_objc_method(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('exclude', 'objc-method', f))
        return self

    def include_java_method(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('include', 'java-method', f))
        return self

    def exclude_java_method(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('exclude', 'java-method', f))
        return self

    def include_debug_symbol(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('include', 'debug-symbol', f))
        return self

    def build(self):
        # 수정됨 : self._findString, self._findHex, self._setEncoding
        return TracerProfile(self._spec, self._findString, self._findHex, self._setEncoding)


class TracerProfile(object):
    def __init__(self, spec, findString, findHex, setEncoding):     # 수정됨 : findString, findHex, allLogs, printConsole, setEncoding
        self.spec = spec
        self.findString = findString            # 수정됨 : self.findString = findString
        self.findHex = findHex                  # 수정됨 : self.findHex = findHex
        self.allLogs = False                    # 수정됨 : self.allLogs = False
        self.printConsole = False               # 수정됨 : self.printConsole = False
        self.setEncoding = setEncoding          # 수정됨 : self.setEncoding = setEncoding

class Finder(object):
    # 수정됨 : payload End 까지
    # 1. send로 보내진 payload를 hex 문자열 슬라이스
    # 2. 디렉토리 생성
    # 3. hex 바이너리를 searching 하고 매치된 문자열 폴더에 해당 핸들러의 이름을 가진 텍스트 파일로 저장
    def __init__(self, payload, profile, script):
        self._payload = payload
        self._profile = profile
        self._script = script
        self._jspayload = payload['jspayload']
        self._opt_allLogs = self._profile.allLogs                         # -A option
        handler = self._jspayload.split('#')
        self._module_name = re.sub("[\\*/:?|<>]", "@", handler[0])        # 모듈 이름 : 파일 및 폴더명으로 생성 못하는 특수문자 @로 대체
        self._handler_name = re.sub("[\\*/:?|<>]", "@", handler[1])       # 핸들러 이름 : 파일 및 폴더명으로 생성 못하는 특수문자 @로 대체
        self._full_name = self._module_name+'-'+self._handler_name+'-'+handler[2]+' '
        handlerPayload_org = handler[3]
        # 후킹한 파라미터가 숫자인 경우
        if re.compile('^[0-9]*[0-9]$').match(handlerPayload_org) : self._handlerPayload_Byte = handlerPayload_org.encode()
        # 후킹한 파라미터가 메모리 주소인 경우
        else : self._handlerPayload_Byte = bytes.fromhex(handlerPayload_org)     # 문자열 hex값을 byte 형식으로 변경
        try : 
            self._detect_result = self.detect_encoding()
            self._handlerPayload_Byte.decode(self._detect_result["encoding"])
            #print("_detect_result : ", self._detect_result)
        except Exception as err: 
            self._detect_result["encoding"] = "utf-8"
        self._handlerPayload = self._full_name+self._handlerPayload_Byte.decode(self._detect_result["encoding"],"backslashreplace")

    def start_find(self):
        self.item_check()

    def detect_encoding(self):
        # detect payload encoding
        user_encoding = self._profile.setEncoding     # 사용자가 옵션으로 넣은 인코딩
        detect_result = {}

        # --set-encoding 옵션이 없는 경우
        if(user_encoding==""): detect_result= chardet.detect(self._handlerPayload_Byte)   # 해당 바이트가 어떤 인코딩을 사용하는지 탐지
        # --set-encoding 옵션이 있는 경우
        else : detect_result["encoding"] = user_encoding
        return detect_result

    def time_check(self):
        # Time Log
        now = datetime.datetime.now()
        return now.strftime('%Y-%m-%d %H:%M:%S')

    def item_check(self):
        # Append
        search_items = []

        # Append String Item
        self._input_strs = self._profile.findString               # TracerProfileBuilder().findString 참조
        for inputStr in self._input_strs :
            # 검색 단어가 한글인데 encoding이 한글이 아닌경우 \\u로 되면서 오류가 나거나 빈칸이 되면서 모두 검색되는 오류가 있어 해결함
            try : input_strs_byte = inputStr.encode(self._detect_result["encoding"])   # bytes(userInput, encoding=result["encoding"]) 이거랑 같은거
            except : input_strs_byte = inputStr.encode("utf-8")
            search_items.append(input_strs_byte)

        # Append Hex Item
        input_hexs = self._profile.findHex                        # TracerProfileBuilder().findHex 참조
        for input_hex in input_hexs :
            input_hexs_byte = bytes.fromhex(input_hex)
            search_items.append(input_hexs_byte)

        # --find 옵션이 없고, -A 옵션만 있을 경우 모두 검색함
        if search_items==[] and self._opt_allLogs : search_items.append(b'.*')
        self.searching(search_items)

    def searching(self,search_items):
        # -C option
        opt_printConsole = self._profile.printConsole

        # Find
        for count, search_item in enumerate(search_items):   # conut로 string, hex 구분, 검색할 문자열을 하나씩
            p = re.compile(search_item,re.IGNORECASE)        # 대소문자 구분 없이 
            m = p.search(self._handlerPayload_Byte)          # send로 넘어오는 payload에 대해 검색함
            if m and search_item!=b'.*':
                # Post Message to JS
                self.post_js(m)
                # Print Logs
                if opt_printConsole: self.print_log(count)
            # Record Log
            if m or self._opt_allLogs : self.save_log(m,search_item,count)

    # 전체 검색이 아니고, 검색된 문자열이 있을경우 hook script(.js)에 메세지 전송
    def post_js(self,m):
        self._script.post({'type': 'findStr', 'payload': m.group().hex(' ')})

    # -C옵션이 있고 검색된 문자열이 있을 경우 콘솔에 출력, len(input_strs)보고 String인지 Hex인지 구분
    def print_log(self,count):
        # Print String
        if count < len(self._input_strs):
            self._handlerPayload = self._full_name+self._handlerPayload_Byte.decode(self._detect_result["encoding"],"backslashreplace")
            print(self._handlerPayload+'\n')

        # Print Hex
        else:
            self._handlerPayload = ""
            handlerPayload_hex = self._handlerPayload_Byte.hex(' ')
            for i in range(0,len(handlerPayload_hex),48): self._handlerPayload += handlerPayload_hex[i:i+48] + '\n'
            self._handlerPayload = self._full_name+'\n'+self._handlerPayload
            print(self._handlerPayload+'\n')

    # 검색된 문자열이 있거나, -A 옵션이 켜져있는 경우 Log가 저장됨
    def save_log(self,m,search_item,count):
        now_datetime = self.time_check()

        # Set Directory
        base_filePath = os.path.join(os.getcwd(), "findHandlers").replace("\\", "\\\\")
        save_dirName = ""

        # --find-string 또는 --find-hex 옵션이 없거나 전체[.*]일 경우, -A 옵션이 설정되었지만 검색된 문자열이 없는 경우 [ALL] 폴더에 저장
        # --find, -A 동시 켜져있을경우 --find 옵션에 걸리는 건 검색된 문자열 폴더에 저장
        if search_item == b'.*' or self._opt_allLogs and m==None : save_dirName = "[All]"
        else : 
            try :
                # detect된 인코딩으로 decode 시도
                if count < len(self._input_strs): save_dirName = re.sub('[\\*/:?|<>]', "@",m.group().decode(self._detect_result["encoding"]))
                # 안될 경우 Hex 값으로 저장
                else : save_dirName = m.group().hex(' ')
            except : save_dirName = m.group().hex(' ')

        save_filepath = base_filePath+"\\\\"+save_dirName+"\\\\"+self._module_name
        if not os.path.isdir(save_filepath): os.makedirs(save_filepath)
        # 찾을 문자열로 폴더를 생성 후 찾은 문자열에 맞는 핸들러 별로 폴더에 저장
        save_file = save_filepath+"\\\\"+self._handler_name
        # 전체경로가 259자까지 제한되어있기 때문에 ".txt"빼고 255자를 파일을 포함한 전체길이로 설정
        if len(save_file) > 255 : save_file = save_file[:255]
        # encoding = 안하면 'cp949' codec can't encode character '\ufffd' in position 17: illegal multibyte sequence
        with open(save_file+".txt", "a", encoding='utf-8') as f:
            f.write('==========================================================================================\n')
            f.write(now_datetime+"\n")
            f.write(self._handlerPayload+"\n")
            f.close()

class Tracer(object):
    def __init__(self, reactor, repository, profile, init_scripts=[], log_handler=None):
        self._reactor = reactor
        self._repository = repository
        self._profile = profile
        self._script = None
        self._agent = None
        self._init_scripts = init_scripts
        self._log_handler = log_handler

    def start_trace(self, session, stage, parameters, runtime, ui):
        def on_create(*args):
            ui.on_trace_handler_create(*args)
        self._repository.on_create(on_create)

        def on_load(*args):
            ui.on_trace_handler_load(*args)
        self._repository.on_load(on_load)

        def on_update(target, handler, source):
            self._agent.update(target.identifier, target.display_name, handler)
        self._repository.on_update(on_update)

        # 수정됨
        def on_message(message, data):
            # message = frida에서 발생되는 모든 메세지, js에서 보낸 send도 포함
            #print(message)
            #print(payload)

            if message['type'] == "send" and message['payload']['type']=='js:send': 
                #print("-------- payload Start ---------")      
                payload = message['payload']
                finder = Finder(payload,self._profile,self._script)
                finder.start_find()
                #print("-------- payload End ---------")
            # _on_message에서 처리된 값을 schedule에 넣음 - application.py에 있음
            else : self._reactor.schedule(lambda: self._on_message(message, data, ui))

        ui.on_trace_progress('initializing')
        data_dir = os.path.dirname(__file__)
        with codecs.open(os.path.join(data_dir, "tracer_agent.js"), 'r', 'utf-8') as f:
            source = f.read()
        runtime = 'v8' if runtime == 'v8' else 'qjs'
        script = session.create_script(name="tracer",
                                       source=source,
                                       runtime=runtime)

        self._script = script
        script.set_log_handler(self._log_handler)
        script.on('message', on_message)
        script.load()
        self._agent = script.exports
        raw_init_scripts = [{ 'filename': script.filename, 'source': script.source } for script in self._init_scripts]
        self._agent.init(stage, parameters, raw_init_scripts, self._profile.spec)

    # 수정됨
    # findhandler폴더의 하위 폴더,파일을 시각화 하는 함수 
    def find_handler(self, base_dir, prefix):
        files = os.listdir(base_dir)
        handler_list = ""
        for file in files:
            path = os.path.join(base_dir, file)
            handler_list += prefix + file +'\n'
            #print(prefix + file)
            if os.path.isdir(path):
                handler_list += self.find_handler(path, prefix + "    ")
        return handler_list


    def stop(self):
        # Stop print('Tracer.stop ')
        # 수정됨 : 찾은 문자열과 관련있는 핸들러들을 모아놓은 텍스트 파일 생성
        # Create find handler list textfile
        root_dir = os.path.join(os.getcwd()).replace("\\", "\\\\")
        base_dir = root_dir+"\\\\findHandlers"
        if not os.path.isdir(base_dir): os.makedirs(base_dir)
        with open(root_dir+"\\\\findHandlerList.txt", "w", encoding='utf-8') as f: f.write(self.find_handler(base_dir, ""))

        if self._script is not None:
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def string_escape(s, encoding='utf-8'):
        return (s.encode('latin1')         # To bytes, required by 'unicode-escape'
                 .decode('unicode-escape') # Perform the actual octal-escaping decode
                 .encode('latin1')         # 1:1 mapping back to bytes
                 .decode(encoding))        # Decode original encoding

    def _on_message(self, message, data, ui):
        handled = False
        if message['type'] == 'send':
            try:
                payload = message['payload']
                mtype = payload['type']
                params = (mtype, payload, data, ui)
            except:
                # As user scripts may use send() we need to be prepared for this.
                params = None
            if params is not None:
                handled = self._try_handle_message(*params)

        if not handled:
            try :
                pass
            except Exception as err :
                pass
    def _try_handle_message(self, mtype, params, data, ui):
        if mtype == "events:add":
            events = [(timestamp, thread_id, depth, message) for target_id, timestamp, thread_id, depth, message in params['events']]
            ui.on_trace_events(events)
            return True

        if mtype == "handlers:get":            
            flavor = params['flavor']
            base_id = params['baseId']

            scripts = []
            response = {
                'type': "reply:{}".format(base_id),
                'scripts': scripts
            }
            repo = self._repository
            next_id = base_id
            for scope in params['scopes']:
                scope_name = scope['name']
                for member_name in scope['members']:
                    target = TraceTarget(next_id, flavor, scope_name, member_name)
                    next_id += 1
                    handler = repo.ensure_handler(target)
                    scripts.append(handler)
            self._script.post(response)
            
            return True

        if mtype == "agent:initialized":
            ui.on_trace_progress('initialized')
            return True

        if mtype == "agent:started":
            self._repository.commit_handlers()
            ui.on_trace_progress('started', params['count'])
            return True

        if mtype == "agent:warning":
            ui.on_trace_warning(params['message'])
            return True

        if mtype == "agent:error":
            ui.on_trace_error(params['message'])
            return True

        return False


class TraceTarget(object):
    def __init__(self, identifier, flavor, scope, name):
        self.identifier = identifier
        self.flavor = flavor
        self.scope = scope
        if isinstance(name, list):
            self.name = name[0]
            self.display_name = name[1]
        else:
            self.name = name
            self.display_name = name

    def __str__(self):
        return self.display_name


class Repository(object):
    def __init__(self):
        self._on_create_callback = None
        self._on_load_callback = None
        self._on_update_callback = None
        self._decorate = False

    def ensure_handler(self, target):
        raise NotImplementedError("not implemented")

    def commit_handlers(self):
        pass

    def on_create(self, callback):
        self._on_create_callback = callback

    def on_load(self, callback):
        self._on_load_callback = callback

    def on_update(self, callback):
        self._on_update_callback = callback

    def _notify_create(self, target, handler, source):
        if self._on_create_callback is not None:
            self._on_create_callback(target, handler, source)

    def _notify_load(self, target, handler, source):
        if self._on_load_callback is not None:
            self._on_load_callback(target, handler, source)

    def _notify_update(self, target, handler, source):
        if self._on_update_callback is not None:
            self._on_update_callback(target, handler, source)

    def _create_stub_handler(self, target, decorate):
        if target.flavor == 'java':
            return self._create_stub_java_handler(target, decorate)
        else:
            return self._create_stub_native_handler(target, decorate)

    def _create_stub_native_handler(self, target, decorate):
        if target.flavor == 'objc':
            state = {"index": 2}
            def objc_arg(m):
                index = state["index"]
                r = ":${args[%d]} " % index
                state["index"] = index + 1
                return r

            log_str = "`" + re.sub(r':', objc_arg, target.display_name) + "`"
            if log_str.endswith("} ]`"):
                log_str = log_str[:-3] + "]`"
        else:
            for man_section in (2, 3):
                args = []
                try:
                    with open(os.devnull, 'w') as devnull:
                        man_argv = ["man"]
                        if platform.system() != "Darwin":
                            man_argv.extend(["-E", "UTF-8"])
                        man_argv.extend(["-P", "col -b", str(man_section), target.name])
                        output = subprocess.check_output(man_argv, stderr=devnull)
                    match = re.search(r"^SYNOPSIS(?:.|\n)*?((?:^.+$\n)* {5}\w+[ \*\n]*" + target.name + r"\((?:.+\,\s*?$\n)*?(?:.+\;$\n))(?:.|\n)*^DESCRIPTION", output.decode('UTF-8', errors='replace'), re.MULTILINE)
                    if match:
                        decl = match.group(1)

                        for argm in re.finditer(r"[\(,]\s*(.+?)\s*\b(\w+)(?=[,\)])", decl):
                            typ = argm.group(1)
                            arg = argm.group(2)
                            if arg == "void":
                                continue
                            if arg == "...":
                                args.append("\", ...\" +");
                                continue

                            read_ops = ""
                            annotate_pre = ""
                            annotate_post = ""

                            normalized_type = re.sub(r"\s+", "", typ)
                            if normalized_type.endswith("*restrict"):
                                normalized_type = normalized_type[:-8]
                            if normalized_type in ("char*", "constchar*"):
                                read_ops = ".readUtf8String()"
                                annotate_pre = "\""
                                annotate_post = "\""

                            arg_index = len(args)

                            args.append("%(arg_name)s=%(annotate_pre)s${args[%(arg_index)s]%(read_ops)s}%(annotate_post)s" % {
                                "arg_name": arg,
                                "arg_index": arg_index,
                                "read_ops": read_ops,
                                "annotate_pre": annotate_pre,
                                "annotate_post": annotate_post
                            })
                        break
                except Exception as e:
                    pass

            if decorate:
                module_string = " [%s]" % os.path.basename(target.scope)
            else:
                module_string = ""

            if len(args) == 0:
                log_str = "'%(name)s()%(module_string)s'" % { "name": target.name, "module_string" : module_string }
            else:
                log_str = "`%(name)s(%(args)s)%(module_string)s`" % {
                    "name": target.name,
                    "args": ", ".join(args),
                    "module_string": module_string
                }
        # 수정됨 : js 파일 생성 시 내부 스크립트
        module_name = os.path.basename(target.scope)
        return """\
/*
 * Auto-generated by Frida. Please modify to match the signature of %(display_name)s.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

{
  /**
   * Called synchronously when about to call %(display_name)s.
   *
   * @this {object} - Object allowing you to store state for use in onLeave.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {array} args - Function arguments represented as an array of NativePointer objects.
   * For example use args[0].readUtf8String() if the first argument is a pointer to a C string encoded as UTF-8.
   * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
   * @param {object} state - Object allowing you to keep state across function calls.
   * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
   * However, do not use this to store function arguments across onEnter/onLeave, but instead
   * use "this" which is an object for keeping state local to an invocation.
   */
  onEnter(log, args, state) {
    //log(%(log_str)s);
    //console.log('==========================================================================================');    
    //console.log('[%(display_name)s]'); 
    //console.log(Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n "));
    function hexConvert(addr,size){var hexResult = ""; var buf = Memory.readByteArray(addr,size);var hexArray = new Uint8Array(buf);for(var i = 0; i < hexArray.length; i++){if(hexArray[i].toString(16).length%%2==1){hexResult += ("0"+hexArray[i].toString(16) + " "); }else{hexResult += (hexArray[i].toString(16) + " "); } }return hexResult.trim();}
    for(i=0; i<10; i++){
        try{
            //var argStr=String(Memory.readUtf16String(args[i])); 
            //var argStr=String(Memory.readAnsiString(args[i])); 
            var argStr=String(Memory.readCString(args[i])); 
            if(argStr==null || argStr=="" || argStr=="null" || argStr.trim().length < 1 || argStr.trim().length > 3000){continue; }
            arg_len = Number('0x'+argStr.length.toString(16)); 
            strHex = "%(module_name)s#%(display_name)s#["+i+"]#"+hexConvert(args[i],arg_len); 
        }catch(err){
            var argStr = parseInt(args[i]); 
            if(argStr==null || argStr=="" || argStr=="null" || argStr.length < 1 ){continue; }
            strHex = "%(module_name)s#%(display_name)s#["+i+"]#"+argStr; 
        }

        try{       
            send_payload = {'type':'js:send','jspayload' : strHex}
            send(send_payload);                                                              // send "js:send" and string type hex payload to python
            //Thread.sleep(0.006);                                                           // wait for recv
            //var op = recv('findStr',function(value) { return payload = value.payload });   // recv payload from python
            
            flag = false; 
            //flag = strHex.includes(payload);              // check find String
            //flag = argStr.includes("User Input"); 
            if(flag){ 
                // Input User Javascript
                //console.log('[*] DATA: %(display_name)s ['+i+'] '+ argStr); 
            }
        }catch(err){
            //console.log(err)
            //console.log('[*] DATA: %(display_name)s ['+i+'] '+ argStr); 
        }
    }
    
  },

  /**
   * Called synchronously when about to return from %(display_name)s.
   *
   * See onEnter for details.
   *
   * @this {object} - Object allowing you to access state stored in onEnter.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {NativePointer} retval - Return value represented as a NativePointer object.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onLeave(log, retval, state) {
    function hexConvert(addr,size){var hexResult = ""; var buf = Memory.readByteArray(addr,size);var hexArray = new Uint8Array(buf);for(var i = 0; i < hexArray.length; i++){if(hexArray[i].toString(16).length%%2==1){hexResult += ("0"+hexArray[i].toString(16) + " "); }else{hexResult += (hexArray[i].toString(16) + " "); } }return hexResult.trim();}
    try{
        //var argStr=String(Memory.readUtf16String(retval)); 
        //var argStr=String(Memory.readAnsiString(retval)); 
        var argStr=String(Memory.readCString(retval)); 
        if(argStr==null || argStr=="" || argStr=="null" || argStr.trim().length < 1 || argStr.trim().length > 3000){ }
        arg_len = Number('0x'+argStr.length.toString(16)); 
        strHex = "%(module_name)s#%(display_name)s#retval#"+hexConvert(retval,arg_len);
    }catch(err){
        var argStr = parseInt(retval); 
        if(argStr==null || argStr=="" || argStr=="null" || argStr.length < 1 ){ }
        strHex = "%(module_name)s#%(display_name)s#retval#"+argStr; 
    }

    try{
        send_payload = {'type':'js:send','jspayload' : strHex}
        send(send_payload);                                                              // send "js:send" and string type hex payload to python
        //Thread.sleep(0.006);                                                           // wait for recv
        //var op = recv('findStr',function(value) { return payload = value.payload });   // recv payload from python
        
        flag = false; 
        //flag = strHex.includes(payload);              // check find String
        //flag = argStr.includes("User Input"); 
        if(flag){ 
            // Input User Javascript
            //console.log('[*] DATA: %(display_name)s retval '+ argStr); 
        }
    }catch(err){
        //console.log(err)
        //console.log('[*] DATA: %(display_name)s retval '+ argStr); 
    }
  }
}
""" % {"display_name": target.display_name, "log_str": log_str, "module_name": module_name}

    def _create_stub_java_handler(self, target, decorate):
        module_name = os.path.basename(target.scope)
        return """\
/*
 * Auto-generated by Frida. Please modify to match the signature of %(display_name)s.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

{
  /**
   * Called synchronously when about to call %(display_name)s.
   *
   * @this {object} - The Java class or instance.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {array} args - Java method arguments.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onEnter(log, args, state) {

    //log(`%(display_name)s(${args.map(JSON.stringify).join(', ')})`);
    //console.log('==========================================================================================');    
    //console.log('[%(display_name)s]'); 
    //console.log(Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n "));
    function JNIhexConvert(value){ var hexResult = ""; for(var i = 0; i < value.length; i++){ hexValue = value.charCodeAt(i).toString(16); if(hexValue.length%%2==1){ hexResult += ("0"+hexValue+" ");  }else{ hexResult += (hexValue+" "); } }return hexResult.trim(); }
    for(i=0;i<10;i++){
      try{
        var argStr=String(args.map(JSON.stringify)[i]);
        if(argStr==undefined || argStr=="undefined"){ break; }
        if(argStr=="" || argStr.trim().length < 1){ }
        else{ 
            strHex = "%(module_name)s#%(display_name)s#["+i+"]#"+JNIhexConvert(argStr);
            send_payload = {'type':'js:send','jspayload' : strHex}
            send(send_payload);                                                              // send "js:send" and string type hex payload to python
            //Thread.sleep(0.006);                                                           // wait for recv
            //var op = recv('findStr',function(value) { return payload = value.payload });   // recv payload from python
            
            flag = false;
            //flag = strHex.includes(payload);              // check find String
            //flag = argStr.includes("User Input");
            if(flag){ 
                // Input User Javascript
                //console.log('[*] DATA: %(display_name)s ['+i+'] '+ argStr); 
            }
        }
      }catch(err){ }
    }
  },

  /**
   * Called synchronously when about to return from %(display_name)s.
   *
   * See onEnter for details.
   *
   * @this {object} - The Java class or instance.
   * @param {function} log - Call this function with a string to be presented to the user.
   * @param {NativePointer} retval - Return value.
   * @param {object} state - Object allowing you to keep state across function calls.
   */
  onLeave(log, retval, state) {
    if (retval !== undefined) {
      function describeJavaClass(className) {var jClass = Java.use(className);console.log(JSON.stringify({_name: className,_methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {return !m.startsWith('$') || m == 'class' || m == 'constructor'}), _fields: jClass.class.getFields().map(f => {return f.toString()})  }, null, 2));}
      function JNIhexConvert(value){ var hexResult = ""; for(var i = 0; i < value.length; i++){ hexValue = value.charCodeAt(i).toString(16); if(hexValue.length%%2==1){ hexResult += ("0"+hexValue+" ");  }else{ hexResult += (hexValue+" "); } }return hexResult.trim(); }
      //log(`<= ${JSON.stringify(retval)}`);

       try{
           var argStr=String(JSON.stringify(retval));
           if(argStr==undefined || argStr=="" || argStr.trim().length < 1){ }
           else{ 
               strHex = "%(module_name)s#%(display_name)s#retval#"+JNIhexConvert(argStr);
               send_payload = {'type':'js:send','jspayload' : strHex}
               send(send_payload);                                                              // send "js:send" and string type hex payload to python
               //Thread.sleep(0.006);                                                           // wait for recv
               //var op = recv('findStr',function(value) { return payload = value.payload });   // recv payload from python
               
               //describeJavaClass("%(module_name)s");

               flag = false;
               //flag = strHex.includes(payload);               // check find String
               //flag = argStr.includes("User Input");        
               if(flag){ 
                   // Input User Javascript
                   // console.log('[*] DATA: %(display_name)s retval '+ argStr); 
               }
           }
       }catch(err){ }
    }
  }
}
""" % {"display_name": target.display_name, "module_name": module_name}


class MemoryRepository(Repository):
    def __init__(self):
        super(MemoryRepository, self).__init__()
        self._handlers = {}

    def ensure_handler(self, target):
        handler = self._handlers.get(target)
        if handler is None:
            handler = self._create_stub_handler(target, False)
            self._handlers[target] = handler
            self._notify_create(target, handler, "memory")
        else:
            self._notify_load(target, handler, "memory")
        return handler


class FileRepository(Repository):
    def __init__(self, reactor, decorate):
        super(FileRepository, self).__init__()
        self._reactor = reactor
        self._handler_by_id = {}
        self._handler_by_file = {}
        self._changed_files = set()
        self._last_change_id = 0
        self._repo_dir = os.path.join(os.getcwd(), "__handlers__")
        self._repo_monitors = {}
        self._decorate = decorate

    def ensure_handler(self, target):
        entry = self._handler_by_id.get(target.identifier)
        if entry is not None:
            (target, handler, handler_file) = entry
            return handler

        handler = None

        scope = target.scope
        if len(scope) > 0:
            handler_file = os.path.join(self._repo_dir, to_filename(os.path.basename(scope)), to_handler_filename(target.name))
        else:
            handler_file = os.path.join(self._repo_dir, to_handler_filename(target.name))

        if os.path.isfile(handler_file):
            with codecs.open(handler_file, 'r', 'utf-8') as f:
                handler = f.read()
            self._notify_load(target, handler, handler_file)

        if handler is None:
            handler = self._create_stub_handler(target, self._decorate)
            handler_dir = os.path.dirname(handler_file)
            if not os.path.isdir(handler_dir):
                os.makedirs(handler_dir)
            with open(handler_file, 'w') as f:
            # 수정 15.1.17
            #with codecs.open(handler_file, 'w', 'utf-8') as f:
                f.write(handler)
            self._notify_create(target, handler, handler_file)

        entry = (target, handler, handler_file)
        self._handler_by_id[target.identifier] = entry
        self._handler_by_file[handler_file] = entry

        self._ensure_monitor(handler_file)

        return handler

    def _ensure_monitor(self, handler_file):
        handler_dir = os.path.dirname(handler_file)
        monitor = self._repo_monitors.get(handler_dir)
        if monitor is None:
            monitor = frida.FileMonitor(handler_dir)
            monitor.on('change', self._on_change)
            self._repo_monitors[handler_dir] = monitor

    def commit_handlers(self):
        for monitor in self._repo_monitors.values():
            monitor.enable()

    def _on_change(self, changed_file, other_file, event_type):
        if changed_file not in self._handler_by_file or event_type == 'changes-done-hint':
            return
        self._changed_files.add(changed_file)
        self._last_change_id += 1
        change_id = self._last_change_id
        self._reactor.schedule(lambda: self._sync_handlers(change_id), delay=0.05)

    def _sync_handlers(self, change_id):
        if change_id != self._last_change_id:
            return
        changes = self._changed_files.copy()
        self._changed_files.clear()
        for changed_handler_file in changes:
            (target, old_handler, handler_file) = self._handler_by_file[changed_handler_file]
            with codecs.open(handler_file, 'r', 'utf-8') as f:
                new_handler = f.read()
            changed = new_handler != old_handler
            if changed:
                entry = (target, new_handler, handler_file)
                self._handler_by_id[target.identifier] = entry
                self._handler_by_file[handler_file] = entry
                self._notify_update(target, new_handler, handler_file)


class InitScript(object):
    def __init__(self, filename, source):
        self.filename = filename
        self.source = source


class OutputFile(object):
    def __init__(self, filename):
        # 수정됨
        print('OutputFile.__init__')
        print(filename)
        self._fd = codecs.open(filename, 'wb', 'utf-8')

    def close(self):
        # 수정됨 
        print('OutputFile.close')
        print(self._fd)
        self._fd.close()

    def append(self, message):
        self._fd.write(message)
        self._fd.flush()


class UI(object):
    def on_trace_progress(self, status):
        pass

    def on_trace_warning(self, message):
        pass

    def on_trace_error(self, message):
        pass

    def on_trace_events(self, events):
        pass

    def on_trace_handler_create(self, target, handler, source):
        pass

    def on_trace_handler_load(self, target, handler, source):
        pass


def to_filename(name):
    result = ""
    for c in name:
        if c.isalnum() or c == ".":
            result += c
        else:
            result += "_"
    return result


def to_handler_filename(name):
    full_filename = to_filename(name)
    if len(full_filename) <= 41:
        return full_filename + ".js"
    crc = binascii.crc32(full_filename.encode())
    return full_filename[0:32] + "_%08x.js" % crc


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

