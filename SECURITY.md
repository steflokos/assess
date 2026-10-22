# Security

## Report a problem

Please do not open a public issue for a security problem. Use the private vulnerability reporting of this repository
instead: open the Security tab and choose "Report a vulnerability". Say what you ran, what you expected and what happened. A
small project that shows the problem helps most.

## What counts

assess runs on your machine and reads and writes the files of a project. These are the problems that matter:

- A command writes a file outside the project folder.
- A project file, a change set or a rule makes assess run code or read a file it should not.
- The report runs a script that is not its own.
- A web page that is not the interface of `assess serve` can read or change a project through it, or the server listens on an
  address that is not on this computer.
- A closed iteration can be changed and `assess verify` still says the chain is intact.
- A signature that is not valid passes `assess verify`.

## Versions

Only the latest release gets fixes. assess is a beta (0.x) and the format of a project may change between minor versions.
See "Versions and compatibility" in the README.

## Your keys

assess never stores your private signing key. Keep it somewhere that the project folder cannot reach.
