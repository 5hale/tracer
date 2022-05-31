# tracer
- tracer는 frida-tools에서 제공하는 frida-trace 툴에 몇 가지 옵션을 추가한 스크립트

## 설치(Install)
1. frida 및 frida-tools 설치 필요
2. "\[Python Path\]\Lib\site-packages\frida_tools" 디렉토리 내 `tracer.py`를 본 스크립트 파일로 변경

## 종속성(dependencies)
- chardet
- datetime
- json

## 추가된 옵션(Add Option)
<details>
<summary>--find-string</summary>
<div markdown="1">

- 입력한 키워드를 후킹된 함수의 파라미터와 매치되는 문자열이 있을 경우 findHandlers라는 폴더에 로깅함
- 알파벳, 한글, 숫자 검색이 가능하며, 기본적으로 알파벳의 대소문자는 구분하지 않음
- 키워드는 기본적으로 python regex(re.py)를 통해 동작함
- regex 구문에 문제가 있을 경우 오류가 발생함
- regex의 모두 선택 구문인 `.*` 만 입력할 경우 동작 하지 않음

#### usage
``` powershell
frida-trace --find-string "< regex | string | number | 한글 >"
```
#### ex
``` powershell
frida-trace --find-string ".*ab.cd.|frida|1234|프리다"
```
</div>
</details>

<details>
<summary>--find-hex</summary>
<div markdown="1">

- 입력한 Hex 키워드를 후킹된 함수의 파라미터와 매치되는 Hex가 있을 경우 findHandlers라는 폴더에 로깅함
- hex값으로 출력됨
#### usage
``` powershell
frida-trace --find-hex "< hex >"
```
#### ex
``` powershell
frida-trace --find-hex "00 01 02 03 04 05 06"
```
</div>
</details>

<details>
<summary>--set-encoding</summary>
<div markdown="1">

- `-C` 옵션 사용 시 콘솔에 출력되는 인코딩에 대하여 설정 가능
- python에서 지원하는 모든 인코딩 지원

#### usage
``` powershell
frida-trace --set-encoding "<encoding>"
```
#### ex
``` powershell
frida-trace --set-encoding "utf-8"
```
</div>
</details>

<details>
<summary>-C</summary>
<div markdown="1">

- `--find-string`, `--find-hex`에서 입력값과 매칭된 파라미터를 콘솔에 출력함
- 콘솔에 출력할 내용이 많을수록 부하가 많이 걸림
- 사용할 때 출력이 너무 많지 않은 함수에서만 사용
- 💡 `--find-string ".*" -C` 의 경우 매칭되어도 출력되지 않음

#### usage
``` powershell
frida-trace -C
```
#### ex
``` powershell
frida-trace --find-string "test" -C
```
</div>
</details>

<details>
<summary>-A</summary>
<div markdown="1">

- 후킹된 함수의 모든 파라미터를 로깅함
- 콘솔 화면에는 출력되지 않음

#### usage
``` powershell
frida-trace -A
```

#### 💡 -A옵션과 -C옵션을 같이 사용할 경우 
- 모든 파라미터가 출력되지 않음
- `--find-string`, `--find-hex`에서 찾은 문자열만 콘솔에 출력
- -A는 파라미터를 log에 저장하는 기능으로서만 동작함
<a>
💡 모든 파라미터 출력이 필요하다면 tracer.py를 수정하거나, js파일에 console.log()를 통해 출력하는 것을 권장
</a>
</div>
</details>

<details>
<summary>--json</summary>
<div markdown="1">

- **양식에 맞춘 json 파일** 입력 시 **사용자 함수**를 대상으로 후킹을 시도함
- --json 사용 시 입력되는 파라미터는 `json_file` 을 제외하고 모두 선택사항임
- [idatojson](https://github.com/5hale/idatosjson)을 사용하여 IDA에서 JSON 파일 추출
<details>
<summary>json 양식</summary>
<div markdown="1">

```json
{
	"Module" : "<module_name>",
	"<section_name>":[
		{
				"Name" : "<Func_name>",
				"Address" : "<Func_offset>"
		},
		{
				"Name" : "<Func_name>",
				"Address" : "<Func_offset>"
		}
	],
	"<section_name>":[
		{
				"Name" : "<Func_name>",
				"Address" : "<Func_offset>"
		}
	]
}
```

</div>
</details>

#### usage
``` powershell
frida-trace --json "<json_file::[start_addr::end_addr::hook_count::start_index::section]>"
```
#### ex
``` powershell
# test.json에 있는 함수를 후킹함
frida-trace --json "C:\test.json"

# test.json의 0x8f90 주소부터 2개의 함수를 후킹함
frida-trace --json "C:\test.json::0x8f0::::2"

# test.json의 0x8f90에서 0x9ac에 있는 함수를 후킹함
frida-trace --json "C:\test.json::0x8f0::0x9ac"

# start_index를 100번으로 설정하고 5개를 후킹함
frida-trace --json "C:\test.json::::::5::100"

# text 섹션의 함수를 100개 후킹함
frida-trace --json "C:\test.json::::::100::::text"
```
---

#### 입력 파라미터 설명

- 입력파라미터는 `json_file::start_addr::end_addr::hook_count::start_index::section`로 총 6개 파라미터가 있으며 `::` 로 서로 위치가 구분됨
- `json_file` 이외에는 default 값이 설정되어 있거나 없어도 동작함
	<details>
	<summary>parameter default</summary>
	<div markdown="1">

	- start_addr = None
	- end_addr = None
	- hook_count = 2000
	- start_index = 0
	- section = text

	</div>
	</details>

- **json_file**
	- 데이터를 가져올 JSON 파일을 설정함
    - 상대 및 절대경로 사용 가능
    - 해당 JSON파일은 양식에 맞게 설정되어 있어야함
- **start_addr**, **end_addr**
	- 해당 모듈의 시작 주소와 마지막 주소를 설정
    - 해당 주소는 이 주소 보다 작다, 크다가 아닌 정확히 후킹할 주소 값이어야 함
    - `start_addr`만 설정이 가능하며, 해당 경우 `hook_count`로 후킹할 갯수가 선정됨
    - `end_addr`만 입력할 경우 첫 주소는 0에 가까운 주소부터 `hook_count`만큼 후킹함
    - `start_addr`과 `end_addr`을 같이 설정할 경우 **“2000”**개가 넘지않는 이상 두 주소 사이에 있는 함수가 후킹됨
- **hook_count**
	- 후킹할 함수의 갯수를 설정함
    - `start_addr`, `end_addr`가 동시에 설정되어 있는경우 우선순위에서 밀림
    - `end_addr`이 없을 경우 `hook_count`는 입력한 값을 우선으로함
    - `hook_count`는 **2000**개를 넘기지 않음
- **start_index**
	- 시작 index를 설정함
    - 해당 기능의 의의는 주소를 이용하지 않고 간편하게 십진수로 이용하여 무차별적인 후킹을 위함
    - `start_addr`가 설정되어 있는경우 우선순위에서 밀림
- **section**
	- JSON에서 가져올 섹션을 선택함

---
</div>
</details>


## Usage

```powershell
frida-trace -i "*memcpy*" --find-string "frida|프리다" -C -A -U -f com.package.test
# frida-trace -U -f com.package.test : com.package.test을 spawn과 동시에 attach
# -i "*memcpy*" : "memcpy" 문자열을 가진 모든 함수를 후킹
# --find-string "frida|프리다" : 후킹된 함수의 파라미터에서 "frida" 또는 "프리다" 문자열 검색
# -C : 매치된 함수의 파라미터를 콘솔에 출력
# -A : "memcpy" 문자열을 가진 후킹된 함수의 모든 파라미터를 로깅
```