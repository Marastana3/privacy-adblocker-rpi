export default function PrivacyBanner({ privacy }) {
  if (!privacy) return null;
  return (
    <div className="privacy-banner">
      <strong>Privacy mode: {privacy.mode}</strong>
      <span className="muted"> — {privacy.retention}</span>
    </div>
  );
}
