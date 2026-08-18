# Docker Compose — Container 모드 권한 Profile

`EC2-Docker-Compose-통합-아키텍처.md`의 Container 모드를 실제로 돌리기 위한 Compose 파일입니다. Terraform이 만들지 않는 부분(README의 "이 코드가 만들지 않는 것")을 여기서 채웁니다.

## 아직 없는 것 (의도적)

- 실제 Agent 이미지 — 다른 팀이 만드는 공통 Backend/Agent가 준비되면 `image:`를 교체합니다. 지금은 권한 경계 자체를 검증하는 목적이라 `alpine`으로 대체.
- Policy Gateway, Container Executor 분리 — 지금은 Agent 컨테이너가 직접 Canary에 접근하는 가장 단순한 형태입니다. Gateway가 준비되면 별도 서비스로 분리해야 합니다.

## EC2에 파일 올리는 법 (지금은 SCP/S3 없이 SSM 세션에 직접 붙여넣기)

SSM 세션 안에서:

```bash
sudo mkdir -p /opt/trial/compose
sudo tee /opt/trial/compose/docker-compose.yml > /dev/null <<'COMPOSE_EOF'
# (docker-compose.yml 내용 붙여넣기)
COMPOSE_EOF

sudo tee /opt/trial/compose/docker-compose.override.mount-rw.yml > /dev/null <<'OVERRIDE_EOF'
# (docker-compose.override.mount-rw.yml 내용 붙여넣기)
OVERRIDE_EOF
```

## 실행 순서

EC2 부트스트랩(`user_data.sh.tpl`)에서 Docker 공식 저장소로 설치하기 때문에 `docker compose`(v2, 띄어쓰기) 플러그인이 기본으로 들어 있습니다. 아래는 전부 v2 명령어 기준입니다.

**참고**: 예전에는 Ubuntu 기본 저장소의 `docker-compose`(v1, 하이픈)를 썼는데, v1.29.2가 최신 Docker 엔진과 궁합이 안 맞아 Profile을 바꿔서 `up -d`만 다시 실행하면 `KeyError: 'ContainerConfig'` 에러가 났습니다(2026-08-14 실습 중 확인). v2로 옮긴 뒤에도 Profile을 바꿀 땐 안전하게 **`down` 먼저 실행해서 완전히 지운 뒤 `up`** 하는 습관은 유지하세요.

```bash
cd /opt/trial/compose

# 1) baseline (mount RO) 로 기동
sudo docker compose up -d

# 2) 컨테이너 안에서 Canary 쓰기 시도 -> 실패해야 정상
sudo docker compose exec agent-executor sh -c "echo container-test >> /canary/protected-file.txt"

# 3) 호스트 auditd에 잡히는지 확인 (호스트 규칙이 bind mount된 inode를 그대로 감시)
sudo ausearch -k canary_access -ts recent | grep -v CONFIG_CHANGE

# 4) mount-rw profile로 전환 (반드시 down 먼저!)
sudo docker compose down
sudo docker compose -f docker-compose.yml -f docker-compose.override.mount-rw.yml up -d

# 5) 다시 쓰기 시도 -> 이번엔 성공해야 정상
sudo docker compose exec agent-executor sh -c "echo container-test >> /canary/protected-file.txt"

# 6) 해시 변화 + auditd + docker logs 모두 확인
sudo /opt/trial/scripts/check_canary.sh
sudo docker logs agent-executor

# 7) 정리
sudo docker compose -f docker-compose.yml -f docker-compose.override.mount-rw.yml down
```

## 결과 기록

이 Trial 결과도 `notes/topics/공통-최소-실험-결과-양식.md` 형식으로 review-queue에 남깁니다. "어떤 권한 조건을 적용했는가"엔 `container-baseline` → `container-mount-rw`로 적으면 됩니다.
