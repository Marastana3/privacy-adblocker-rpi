import { useCallback, useEffect, useState } from "react";
import { api, setApiKey } from "./api.js";
import PrivacyBanner from "./components/PrivacyBanner.jsx";
import StatsCards from "./components/StatsCards.jsx";
import Categories from "./components/Categories.jsx";
import DomainList from "./components/DomainList.jsx";

export default function App() {
  const [privacy, setPrivacy] = useState(null);
  const [stats, setStats] = useState(null);
  const [categories, setCategories] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [blocklist, setBlocklist] = useState({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [key, setKey] = useState("");

  const refresh = useCallback(async () => {
    setError("");
    try {
      const [p, s, c, w, b] = await Promise.all([
        api.privacy(),
        api.stats(),
        api.categories(),
        api.whitelist(),
        api.blocklist(),
      ]);
      setPrivacy(p);
      setStats(s);
      setCategories(c);
      setWhitelist(w);
      setBlocklist(b);
    } catch (e) {
      setError(String(e.message || e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(() => {
      api.stats().then(setStats).catch(() => {});
    }, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  // Wrap a mutating action: set busy, run, surface errors, then refresh.
  async function mutate(fn) {
    setBusy(true);
    setError("");
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  const custom = blocklist.custom ?? [];

  return (
    <div className="app">
      <header className="app-header">
        <h1>Privacy Ad-Blocker</h1>
        <div className="apikey">
          <input
            type="text"
            placeholder="API key (if set)"
            value={key}
            onChange={(e) => {
              setKey(e.target.value);
              setApiKey(e.target.value);
            }}
          />
          <button className="secondary" onClick={refresh} disabled={busy}>
            Refresh
          </button>
        </div>
      </header>

      <PrivacyBanner privacy={privacy} />

      {error && (
        <div className="panel error">
          <strong>Error:</strong> {error}
          <div className="muted">
            Is the backend running, and is the API key correct for write actions?
          </div>
        </div>
      )}

      <div className="panel">
        <h2>Activity</h2>
        <StatsCards stats={stats} />
      </div>

      <div className="panel">
        <h2>Categories</h2>
        <Categories
          categories={categories}
          busy={busy}
          onToggle={(name, enabled) =>
            mutate(() => api.setCategory(name, enabled))
          }
        />
      </div>

      <div className="grid-2">
        <DomainList
          title="Whitelist (always allowed)"
          domains={whitelist}
          busy={busy}
          placeholder="allow.example.com"
          onAdd={(d) => mutate(() => api.addAllow(d))}
          onRemove={(d) => mutate(() => api.removeAllow(d))}
        />
        <DomainList
          title="Custom blocklist"
          domains={custom}
          busy={busy}
          placeholder="block.example.com"
          onAdd={(d) => mutate(() => api.addBlock(d))}
          onRemove={(d) => mutate(() => api.removeBlock(d))}
        />
      </div>
    </div>
  );
}
