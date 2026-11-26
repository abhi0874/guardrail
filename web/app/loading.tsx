export default function Loading() {
  return (
    <div className="page-head" aria-busy="true">
      <h1>Loading workspace…</h1>
      <div className="skeleton" />
    </div>
  );
}
