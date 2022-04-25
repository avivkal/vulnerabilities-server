import express, { Request, Response } from "express";
// import * as nodePortScanner from "node-port-scanner";
const nodePortScanner = require("node-port-scanner");

import { bruteForceSSH } from "./attacks/ssh";
import { SSH_PORT } from "./constants";

const app = express();
const port = 3000;

app.get("/scan", async (req: Request, res: Response) => {
  try {
    const result = await nodePortScanner(req.query.host, [
      21,
      SSH_PORT,
      23,
      25,
      80,
      110,
      123,
      443,
    ]);

    const openPorts = result.ports.open;

    const possibleAttacks: number[] = [];

    openPorts.forEach((port: number) => {
      switch (port) {
        case SSH_PORT:
          bruteForceSSH(possibleAttacks);
          break;
      }
    });

    res.send(possibleAttacks);
  } catch {
    res.send("").status(500);
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
