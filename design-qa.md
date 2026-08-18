# Design QA — 권한 프로파일 한국어 설명

- source visual truth: `C:/Users/vinny/AppData/Local/Temp/codex-clipboard-dad3e9eb-9831-4d6e-9edd-3206489f9961.png`
- implementation screenshot: `C:/Users/vinny/AppData/Local/Temp/permission-description-implementation.png`
- combined comparison: `C:/Users/vinny/AppData/Local/Temp/permission-description-comparison.png`
- viewport: 1265 × 711 CSS px, device scale 1
- source pixels: 1441 × 380
- implementation full-page pixels: 1265 × 1761
- state: Container → DAC override → OFF

## Full-view comparison

기존 Carbon 레이아웃, 권한 상태 스위치, OFF/ON 2열 구조와 선택된 프로파일의 파란색 하단 강조선이 유지됐다. 한국어 설명 추가로 프로파일 카드 높이만 의도적으로 증가했으며 주변 레이아웃을 침범하지 않는다.

## Focused-region comparison

원본 권한 상태·프로파일 영역과 수정된 같은 영역을 하나의 합성 이미지로 비교했다. 기존 영문 Profile ID는 그대로 보존됐고, `비활성 권한 (OFF)`·`활성 권한 (ON)` 제목과 각 상태의 한국어 동작 설명이 추가됐다.

## Required fidelity surfaces

- Fonts and typography: 기존 IBM Plex Sans 계층과 12px 보조 설명 스타일을 유지했다.
- Spacing and layout: 설명 위 8px 간격과 1.5 line-height를 사용했으며 잘림이나 겹침이 없다.
- Colors and tokens: 기존 surface, muted text, IBM Blue 선택 강조색을 그대로 사용했다.
- Image quality and assets: 이 UI 영역에는 비교할 이미지 자산이 없다.
- Copy and content: DAC override의 OFF/ON 의미를 한국어로 구분하면서 원본 Profile ID를 보존했다.

## Findings

P0/P1/P2 차이 없음. 추가된 설명은 사용자 요청에 따른 의도적인 정보 확장이다.

## Verification

- DAC override 선택 상호작용 확인
- 브라우저 콘솔 error/warning 없음
- ESLint 통과
- TypeScript 및 Vite production build 통과

final result: passed

