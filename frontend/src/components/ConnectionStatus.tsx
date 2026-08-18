export type ConnectionState = "connected" | "checking" | "local" | "error";

export interface ServiceConnection {
  id: string;
  label: string;
  state: ConnectionState;
  status: string;
  detail: string;
}

interface ConnectionStatusProps {
  services: ServiceConnection[];
}

export function ConnectionStatus({ services }: ConnectionStatusProps) {
  return (
    <ul aria-label="서비스 연결 상태" aria-live="polite" className="connection-status-list">
      {services.map((service) => (
        <li className={`connection-status is-${service.state}`} key={service.id} title={service.detail}>
          <span aria-hidden="true" className="connection-dot" />
          <span>{service.label}</span>
          <strong>{service.status}</strong>
        </li>
      ))}
    </ul>
  );
}
