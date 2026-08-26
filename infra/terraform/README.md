# Fixed Terraform environment

이 디렉터리는 최소 운영 테스트에서 사용하는 **고정 AWS 인프라 사본**의 위치다.

팀 OS 저장소의 commit `a0152804ddc64d67f220b17125f7987abf24cdec`를 기준으로 사본을 고정했다. 원본 정보는 `SOURCE.lock`, 팀 문서는 `UPSTREAM_README.md`에서 확인한다.

고정 환경은 `fixed.auto.tfvars`에 정의되어 있고 대시보드에서 변경할 수 없다.

- Region/AZ: `us-east-1` / `us-east-1a`
- EC2: `t3.small` 1대
- Network: Private Subnet, public inbound 없음
- Access: SSM only
- Runtime: 같은 EC2의 U1/U2 Host와 C1/C2/C3 Container 방향성 환경 경계
- Services: OS Agent Backend, root-owned Host Supervisor, `c1-target`, `c2-target`, `c3-target`
- Runtime Network: Container Target은 내부 `control` 망에만 연결하고, Backend는 호스트 loopback 게시와 외부 API 호출을 위해 별도 `egress` 망에도 연결

저장·로그 정책:

- Backend Docker image는 ECR에 저장하고 EC2 IAM Role로 pull한다.
- Host Supervisor는 public/TCP port 없이 `/run/os-agent/host-supervisor.sock`에서만 요청을 받는다.
- 백엔드 UID와 Host 실험 사용자 UID를 분리하며, 실험 사용자는 Supervisor socket에 접근할 수 없다.
- S3 리소스는 생성하지 않는다.
- VPC Flow Logs는 CloudWatch Logs에 저장한다.
- `collect_state.sh` Evidence는 Supabase Collector 연동 전까지 EC2 로컬 staging 경로에만 저장한다.
- Terraform state는 최소 테스트 동안 로컬 파일을 사용하며 Git에 커밋하지 않는다.

테스트 중 지켜야 할 규칙:

- 대시보드의 Host/Container 선택은 Terraform 분기가 아니라 U1 또는 C1 Executor 시작점 선택이며, 별도로 8개 방향성 TB 중 하나를 선택한다.
- 한 테스트 묶음이 진행되는 동안 `terraform apply`를 다시 실행하지 않는다.
- OpenRouter 및 Supabase secret을 `tfvars`, state, `user_data` 원문에 넣지 않는다.
- 백엔드 8000 포트는 public inbound로 열지 않고 SSM Port Forwarding으로 연결한다.
- 최초 `terraform init` 후 생성되는 `terraform.lock.hcl`을 고정한다.

## 대시보드 자동 배포 순서

로컬 백엔드의 배포 컨트롤러만 이 디렉터리를 실행할 수 있다. 대시보드는 임의 Terraform 경로, target 또는 변수를 전달하지 않는다.

1. `terraform init -input=false`
2. ECR repository만 우선 apply
3. `backend/` Docker image를 ECR에 push
4. 고정 `backend_image_uri`를 넘겨 전체 apply
5. `terraform output -json`을 대시보드에 표시
6. SSM 관리 노드가 Online이 되면 로컬 `8001`에서 EC2 Backend `8000`으로 터널 연결

대시보드의 `AWS 환경 삭제`는 동일한 로컬 state로 `terraform destroy`를 실행하고, 필요하면 남은 고정 CloudWatch Log Group도 정리한다. EC2만 정지하면 NAT Gateway, VPC Endpoint와 EBS 비용은 남을 수 있으므로 장기간 사용하지 않을 때는 전체 환경을 삭제한다.

실제 AWS 배포 전에 Terraform, AWS CLI v2, Docker와 `whs-team` AWS profile이 필요하다. 세부 실행 방법은 프로젝트 루트의 `실행방법.md`를 참고한다.
