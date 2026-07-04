function Card({ value, label }) {
  return (
    <div className="card">
      <div className="value">{value}</div>
      <div className="label">{label}</div>
    </div>
  );
}

export default function StatsCards({ stats }) {
  const total = stats?.total ?? 0;
  const blocked = stats?.blocked ?? 0;
  const allowed = stats?.allowed ?? 0;
  const rate = total > 0 ? Math.round((blocked / total) * 100) : 0;

  return (
    <div className="cards">
      <Card value={total} label="Total queries" />
      <Card value={blocked} label="Blocked" />
      <Card value={allowed} label="Allowed" />
      <Card value={`${rate}%`} label="Block rate" />
    </div>
  );
}
