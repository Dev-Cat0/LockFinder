# LockFinder

파일/폴더 삭제할 때 **"다른 프로그램에서 사용 중이라 삭제할 수 없습니다"** 뜨면,
누가 붙잡고 있는지 찾아서 바로 종료까지 해주는 Windows용 GUI 도구입니다.

## 기능
- 파일 / 폴더 선택 → 사용 중인 프로그램 목록 표시 (이름, PID, 이유, 실행 경로)
- 선택 종료 / 강제 종료 / 전부 종료
- 종료 후 바로 삭제
- 시스템 핵심 프로세스(csrss, lsass 등)는 종료 차단
- 관리자 권한으로 다시 실행 버튼

## 실행
```
pip install -r requirements.txt
python lockfinder.py
```
경로를 인자로 넘기면 바로 검사합니다: `python lockfinder.py "C:\경로\파일.txt"`

## exe로 만들기
```
pip install pyinstaller
pyinstaller --onefile --noconsole --name LockFinder lockfinder.py
```
`dist/LockFinder.exe`가 생성됩니다.

## 참고
- 파일 잠금은 Windows Restart Manager API로 찾습니다. 폴더는 안의 파일(최대 5000개)을 검사하고,
  작업 폴더로 쓰는 프로세스(예: 해당 폴더에서 열린 터미널)도 찾습니다.
- 일부 프로세스는 관리자 권한이 있어야 보이거나 종료됩니다.
- 프로세스를 종료하면 저장 안 한 작업이 사라질 수 있습니다.
