export default function Categories({ categories, onToggle, busy }) {
  if (!categories?.length) {
    return <p className="muted">No categories loaded.</p>;
  }
  return (
    <div>
      {categories.map((c) => (
        <div className="row" key={c.name}>
          <span>
            {c.name}{" "}
            <span className={`badge ${c.enabled ? "on" : "off"}`}>
              {c.enabled ? "blocking" : "off"}
            </span>
          </span>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => onToggle(c.name, !c.enabled)}
          >
            {c.enabled ? "Disable" : "Enable"}
          </button>
        </div>
      ))}
    </div>
  );
}
