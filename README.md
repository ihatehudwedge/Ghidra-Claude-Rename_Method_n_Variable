# Ghidra-Claude Rename (Method & Variable)

Ghidra에서 디컴파일한 함수를 Claude API로 분석해, 함수명과 지역 변수명을 자동으로 더 읽기 쉬운 이름으로 제안·반영하는 스크립트입니다.

Ghidra에 서드파티 확장을 설치하지 않고, **Ghidra에 내장된 PyGhidra 런타임과 Python 3 표준 라이브러리만으로** 동작하도록 만들었습니다.

## 아키텍처

```
[분석 대상 Ghidra 환경]
   ├─ 함수 디컴파일 (DecompInterface)
   ├─ 디컴파일된 의사코드를 Claude API로 전송 (HTTPS, urllib.request)
   ├─ 응답(JSON)에서 제안된 함수명/변수명 파싱
   └─ Ghidra 프로그램에 이름 반영 (HighFunctionDBUtil, Function.setName)

[외부: api.anthropic.com]
   └─ Claude 모델이 코드를 분석하고 이름 제안 JSON을 반환
```

## 요구 사항

- Ghidra 11.3 이상 (PyGhidra 내장 버전)
- 시스템에 설치된 Python 3.8 이상 (별도 pip 패키지 설치 불필요)
- Claude API 키 (종량제, `platform.claude.com`에서 발급)

## 1. Claude API 키 발급

1. [platform.claude.com](https://platform.claude.com) 접속 후 이메일로 가입/로그인 (Claude.ai 계정과 달라도 무방)
2. **Billing**에서 결제 수단을 등록합니다. 건너뛰면 키를 만들어도 요청이 거부됩니다.
3. **Settings → API Keys** (`platform.claude.com/settings/keys`) → **Create Key**
4. 키 이름을 지정하고(예: `ghidra-vm-analysis`) 생성 — 키는 `sk-ant-`로 시작하며 **이 화면에서 단 한 번만 표시**되므로 즉시 복사해 안전한 곳에 보관합니다.
5. 같은 화면에서 **Spend Limit**을 설정해두는 것을 권장합니다. 스크립트가 다수의 함수를 자동으로 순회하며 API를 호출하므로 예상치 못한 비용 발생을 막기 위함입니다.
6. 이 워크플로 전용 키를 별도로 발급해두면, 유출 시 영향 범위를 좁힐 수 있습니다.

## 2. 파일 배치

이 저장소의 두 파일을 같은 폴더에 함께 둡니다. (경로가 흩어지면 스크립트의 API 키 경로 계산이 어긋납니다.)

```
ghidra-claude/
├── .api                      # 실제 키로 채워넣은 뒤 사용
└── ghidra_claude_rename.py
```

`.api` 파일 내용:

```
ANTHROPIC_API_KEY=sk-ant-실제발급받은키
```

- 절대 git에 커밋하지 마세요. `.gitignore`에 `.api`를 추가하고, 저장소에는 더미 값이 든 `.api.example`만 커밋하는 것을 권장합니다.

## 3. 실행 방법

1. Ghidra를 **일반 `ghidraRun`이 아닌** `support/pyghidraRun.bat`으로 실행합니다.
   - PyGhidra는 Ghidra 배포판에 포함된 공식 기능으로, 별도 확장 설치가 필요 없습니다.
2. 분석 대상 바이너리를 열고 Code Browser에서 자동분석이 끝날 때까지 기다립니다.
3. **Window → Script Manager**로 진입합니다.
4. 우측 상단의 스크립트 디렉토리 관리 아이콘 → **+** 버튼 클릭 → `.api`와 `ghidra_claude_rename.py`가 있는 폴더를 추가합니다.
5. 목록을 새로고침하면 `Claude.AI` 카테고리 아래 `ghidra_claude_rename.py`가 나타납니다. 선택 후 **Run**.
6. 하단 **Console** 창에서 진행 로그를 확인합니다.

```
처리 중: FUN_00401000 @ 00401000
  -> 함수명: parse_config_file (적용됨), 변수 3개 적용 성공 / 0개 실패
처리 중: FUN_00401120 @ 00401120
  ...
완료: 총 12개 함수 처리
```

- `[경고] 변수 '...' 리네임 실패` 줄이 없어야 해당 함수의 변수까지 모두 반영된 것입니다.
- 함수명은 로그에 `(적용됨)`으로 표시되면 실제로 반영된 것이고, 예외가 나면 그 함수 자체가 `[오류] ... 처리 중 예외`로 표시되며 건너뜁니다.

## 4. 문의사항

만약 프로그램에 장애 및 문제가 발생하면 kimsihoon@proton.me 메일로 연락을 주시기 바랍니다.
