import requestHandler from "../server.mjs";

export default async function handler(req, res) {
  try {
    return await requestHandler(req, res);
  } catch (err) {
    console.error("[Vercel Function Fatal Error]", err);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("content-type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        error: "Serverless Function Exception",
        message: err.message,
        stack: err.stack
      }));
    }
  }
}

