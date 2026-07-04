import { useState } from "react";

export default function DomainList({ title, domains, onAdd, onRemove, busy, placeholder }) {
  const [value, setValue] = useState("");

  async function submit(e) {
    e.preventDefault();
    const domain = value.trim();
    if (!domain) return;
    await onAdd(domain);
    setValue("");
  }

  return (
    <div className="panel">
      <h2>{title}</h2>
      {domains.length === 0 && <p className="muted">Empty.</p>}
      {domains.map((d) => (
        <div className="row" key={d}>
          <span>{d}</span>
          <button className="danger" disabled={busy} onClick={() => onRemove(d)}>
            Remove
          </button>
        </div>
      ))}
      <form className="add-row" onSubmit={submit}>
        <input
          type="text"
          value={value}
          placeholder={placeholder}
          onChange={(e) => setValue(e.target.value)}
        />
        <button disabled={busy || !value.trim()}>Add</button>
      </form>
    </div>
  );
}
