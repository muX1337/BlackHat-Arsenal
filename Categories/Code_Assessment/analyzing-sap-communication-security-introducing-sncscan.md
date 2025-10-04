# Analyzing SAP Communication Security: Introducing sncscan

## Description
SAP systems are used around the world to handle crucial business processes and highly confidential data such as financial details or information regarding a company's staff. To ensure confidentiality and integrity, sensitive data, and especially access credentials, must only be transmitted over encrypted communication channels. Transport layer encryption for SAP systems is provided by the Secure Network Communications (SNC) protocol. Currently, the configuration of the SAP SNC protocol (such as the Quality of Protection parameter or the installed CryptoLib) can only be audited with authenticated access to the SAP system or by manually connecting to the system through the SAP GUI. These approaches have additional requirements and are impractical for assessing the security of a larger number of systems.

To address the beforementioned issues, we developed 'sncscan', an SNC scanner, that works without authentication and similar to the various tools that are available to analyze the security of services that use SSL/TLS. To achieve this, 'sncscan' starts SNC handshakes with varying encryption parameters to the tested service and analyzes the returned error messages and responses. This is especially useful in context of professional penetration tests and enables us to identify configuration weaknesses and provide actionable recommendations on improving the transport security in SAP environments.

'sncscan' benefits from the tools and research of the `pysap` project and will be released as Open-Source tool in the OWASP CBAS-SAP project. It aims to enable security researchers, professional penetration testers and SAP basis administrators to verify the correct use of the SNC protocol.

Currently 'sncscan' can analyze the SNC configuration of the SAP Router protocol. The next steps are to implement similar functionality for the protocols DIAG and RFC to increase the coverage of SAP services.

## Code
https://github.com/usdAG
