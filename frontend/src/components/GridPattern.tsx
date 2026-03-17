export function GridPattern() {
  return (
    <div
      className="fixed inset-0 pointer-events-none z-0"
      style={{
        backgroundImage: `
          linear-gradient(rgba(30,41,59,0.25) 1px, transparent 1px),
          linear-gradient(90deg, rgba(30,41,59,0.25) 1px, transparent 1px)
        `,
        backgroundSize: "48px 48px",
      }}
    />
  );
}
