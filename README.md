# DISCLAIMER

:warning: | THIS IS AN EXPERIMENTAL PROJECT. IT IS INSECURE AT THIS STAGE<br/>Please don't start depending on it, and do not use it in production. Large parts of this project are subject to change. | :warning:
:---: | :--- | :---

---

# Vanadium

Vanadium is a Risc-V VM that runs in an embedded Secure Element.

By outsourcing encrypted, authenticated pages to an untrusted client, it allows to run applications (V-Apps) in the element without worrying about the limitations of the embedded platform. You can write V-Apps without worrying about binary size and memory usage: only the code actually used at runtime will be sent to the device for execution, and page swapping with the client happens transparently between the VM and the VM client.


# Repository

This repository is organized in a monorepo structure.

* [docs](docs) - Architecture and technical documentation
* [VM](vm) - The Vanadium Ledger app
* [app-sdk](app-sdk) - Vanadium V-App SDK 
* [client-sdk](client-sdk) - Vanadium V-App client SDK

A [test](apps/test) V-App and client is also available.
