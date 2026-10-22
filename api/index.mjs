import requestHandler from "../server.mjs";

export default async function handler(req, res) {
  try {
    return await requestHandler(req, res);
  } catch (err) {
    console.error("[Vercel Function Fatal Error]", err);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("content-type", "application/json; charset=utf-8");
      const isDev = process.env.NODE_ENV === "development";
      res.end(JSON.stringify({
        error: "Serverless Function Exception",
        message: isDev ? err.message : "Internal error occurred. Please check function logs."
      }));
    }
  }
}

