import sql from "mssql";

export function labTableInjectionQueries(marker) {
  if (
    !/^dojo-attack-test:sql-injection:[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
      marker,
    )
  )
    throw new Error("Invalid SQL injection marker.");
  const select =
    "SELECT TOP (5) CONVERT(nvarchar(128), ItemId) AS ItemId FROM dbo.Items";
  const predicate = "CONVERT(nvarchar(128), ItemId)";
  const input = "' OR 1=1 --";
  return {
    input,
    sample: `/* ${marker}:sample */ ${select} ORDER BY ItemId;`,
    baseline: `/* ${marker}:baseline */ ${select} WHERE ${predicate} = @value ORDER BY ItemId;`,
    quoteProbe: `/* ${marker}:quote-probe */ ${select} WHERE ${predicate} = N''' ORDER BY ItemId;`,
    unsafe: `/* ${marker}:unsafe */ ${select} WHERE ${predicate} = N'${input}'\nORDER BY ItemId;`,
    parameterized: `/* ${marker}:parameterized */ ${select} WHERE ${predicate} = @value ORDER BY ItemId;`,
  };
}

export async function runLabTableInjection(pool, marker) {
  const queries = labTableInjectionQueries(marker);
  const sample = (await pool.request().query(queries.sample)).recordset;
  if (
    !Array.isArray(sample) ||
    sample.length < 2 ||
    sample.length > 5 ||
    sample.some(
      (row) =>
        typeof row.ItemId !== "string" ||
        !row.ItemId ||
        row.ItemId.length > 128,
    ) ||
    new Set(sample.map((row) => row.ItemId)).size !== sample.length
  )
    throw new Error("Lab table needs two to five distinct sample item IDs.");
  const baseline = (
    await pool
      .request()
      .input("value", sql.NVarChar(128), sample[0].ItemId)
      .query(queries.baseline)
  ).recordset;
  let quoteProbeError = 0;
  try {
    await pool.request().query(queries.quoteProbe);
  } catch (error) {
    if (error.code !== "EREQUEST" || ![102, 105].includes(error.number))
      throw error;
    quoteProbeError = error.number;
  }
  if (!quoteProbeError)
    throw new Error("Expected quote-probe syntax error was not observed.");
  const unsafe = (await pool.request().query(queries.unsafe)).recordset;
  const parameterized = (
    await pool
      .request()
      .input("value", sql.NVarChar(128), queries.input)
      .query(queries.parameterized)
  ).recordset;
  if (
    !Array.isArray(baseline) ||
    baseline.length !== 1 ||
    baseline[0].ItemId !== sample[0].ItemId ||
    !Array.isArray(unsafe) ||
    unsafe.length !== sample.length ||
    unsafe.some((row, index) => row.ItemId !== sample[index].ItemId) ||
    !Array.isArray(parameterized) ||
    parameterized.length !== 0
  )
    throw new Error(
      "Lab-table comparison returned unexpected results or the sample changed during execution.",
    );
  return {
    detail: `Read-only lookup on dbo.Items: one baseline match, ${unsafe.length} capped unsafe matches, zero parameterized matches, and client-observed SQL syntax error ${quoteProbeError}. Only existing item IDs were read internally; no business rows are returned or modified. This isolated direct-SQL comparison does not establish an HTTP endpoint vulnerability or a Defender detection.`,
    comparison: {
      dataMode: "lab-table",
      table: "dbo.Items",
      rowLimit: 5,
      baselineMatches: baseline.length,
      unsafeMatches: unsafe.length,
      parameterizedMatches: parameterized.length,
      quoteProbeError,
      synthetic: false,
    },
  };
}
