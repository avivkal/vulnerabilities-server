export interface IVulnObject {
  port: number;
  severity: number;
  vulnerabilities: string[];
}

export interface IClientJson {
  vulnObjects: IVulnObject[];
  numOfVulnerabilities: number;
}
