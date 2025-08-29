import { useEffect, useState } from "react";

type AnalysisProps = { data: any };

type Row = {
  no: number;
  time: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
};

function Table({ data }: AnalysisProps) {
  console.log(data);
  const [monitorData, setMonitorData] = useState<Row[]>([]);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(25);


  useEffect(() => {
    if (Array.isArray(data?.data)) {
      setMonitorData(data.data as Row[]);
    } else {
      setMonitorData([]);
    }
    setCurrentPage(1);
  }, [data]);

  return (
    <div className="p-5">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ fontWeight: 600, fontSize: 18 }}>Packets</div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <label style={{ fontSize: 12, color: "#555" }}>Rows per page:</label>
          <select
            value={pageSize}
            onChange={(e) => {
              const size = parseInt(e.target.value, 10);
              setPageSize(size);
              setCurrentPage(1);
            }}
            style={{ padding: "6px 8px", border: "1px solid #ddd", borderRadius: 6 }}
          >
            {[10, 25, 50, 100].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {monitorData.length === 0 ? (
        <div style={{ padding: 12, color: "#666" }}>No data</div>
      ) : (
        <>
          <div style={{ overflowX: "auto", border: "1px solid #eee", borderRadius: 8 }}>
            <table style={{ width: "100%", borderCollapse: "separate", borderSpacing: 0, fontSize: 14 }}>
              <thead>
                <tr>
                  {[
                    "No.",
                    "Time",
                    "Timestamp",
                    "Source",
                    "Destination",
                    "Protocol",
                    "Length",
                    "Info",
                  ].map((h) => (
                    <th
                      key={h}
                      style={{
                        position: "sticky",
                        top: 0,
                        background: "#fafafa",
                        textAlign: "left",
                        padding: "10px 12px",
                        borderBottom: "1px solid #eaeaea",
                        zIndex: 1,
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(() => {
                  const total = monitorData.length;
                  const totalPages = Math.max(1, Math.ceil(total / pageSize));
                  const safePage = Math.min(Math.max(currentPage, 1), totalPages);
                  const start = (safePage - 1) * pageSize;
                  const rows = monitorData.slice(start, start + pageSize);
                  return rows.map((row: Row, idx: number) => (
                    <tr
                      key={`${row.no}-${idx}`}
                      style={{ background: idx % 2 === 0 ? "#fff" : "#fcfcfd" }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "#f7f9fc")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = idx % 2 === 0 ? "#fff" : "#fcfcfd")}
                    >
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", whiteSpace: "nowrap" }}>{row.no}</td>
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums" }}>{row.time}</td>
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", whiteSpace: "nowrap" }}>{row.timestamp}</td>
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", whiteSpace: "nowrap" }}>{row.source}</td>
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", whiteSpace: "nowrap" }}>{row.destination}</td>
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", whiteSpace: "nowrap", fontWeight: 600 }}>{row.protocol}</td>
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums" }}>{row.length}</td>
                      <td style={{ padding: "10px 12px", borderBottom: "1px solid #f1f1f1", maxWidth: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={row.info}>{row.info}</td>
                    </tr>
                  ));
                })()}
              </tbody>
            </table>
          </div>

          {(() => {
            const total = monitorData.length;
            const totalPages = Math.max(1, Math.ceil(total / pageSize));
            const safePage = Math.min(Math.max(currentPage, 1), totalPages);
            const canPrev = safePage > 1;
            const canNext = safePage < totalPages;

            const goTo = (p: number) => setCurrentPage(Math.min(Math.max(p, 1), totalPages));

            const visiblePages = () => {
              const pages: number[] = [];
              const windowSize = 5;
              let start = Math.max(1, safePage - Math.floor(windowSize / 2));
              let end = Math.min(totalPages, start + windowSize - 1);
              if (end - start + 1 < windowSize) {
                start = Math.max(1, end - windowSize + 1);
              }
              for (let i = start; i <= end; i++) pages.push(i);
              return pages;
            };

            return (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12 }}>
                <div style={{ fontSize: 12, color: "#666" }}>
                  Page {safePage} of {totalPages} • {total} rows
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    onClick={() => goTo(1)}
                    disabled={!canPrev}
                    style={{ padding: "6px 10px", border: "1px solid #ddd", borderRadius: 6, background: canPrev ? "#fff" : "#f5f5f5", cursor: canPrev ? "pointer" : "not-allowed" }}
                  >
                    « First
                  </button>
                  <button
                    onClick={() => goTo(safePage - 1)}
                    disabled={!canPrev}
                    style={{ padding: "6px 10px", border: "1px solid #ddd", borderRadius: 6, background: canPrev ? "#fff" : "#f5f5f5", cursor: canPrev ? "pointer" : "not-allowed" }}
                  >
                    ‹ Prev
                  </button>
                  {visiblePages().map((p) => (
                    <button
                      key={p}
                      onClick={() => goTo(p)}
                      style={{
                        padding: "6px 10px",
                        border: "1px solid #ddd",
                        borderRadius: 6,
                        background: p === safePage ? "#111" : "#fff",
                        color: p === safePage ? "#fff" : "#111",
                        cursor: "pointer",
                      }}
                    >
                      {p}
                    </button>
                  ))}
                  <button
                    onClick={() => goTo(safePage + 1)}
                    disabled={!canNext}
                    style={{ padding: "6px 10px", border: "1px solid #ddd", borderRadius: 6, background: canNext ? "#fff" : "#f5f5f5", cursor: canNext ? "pointer" : "not-allowed" }}
                  >
                    Next ›
                  </button>
                  <button
                    onClick={() => goTo(totalPages)}
                    disabled={!canNext}
                    style={{ padding: "6px 10px", border: "1px solid #ddd", borderRadius: 6, background: canNext ? "#fff" : "#f5f5f5", cursor: canNext ? "pointer" : "not-allowed" }}
                  >
                    Last »
                  </button>
                </div>
              </div>
            );
          })()}
        </>
      )}
    </div>
  );
}

export default Table;
