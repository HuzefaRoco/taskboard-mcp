# Taskboard

A small taskboard whose Tasks are viewed on a website but created and changed through ChatGPT.

## Language

**User**:
A person who owns Tasks and connects their ChatGPT to the taskboard. Identified by email.
_Avoid_: Account, member, customer

**Task**:
A single to-do owned by exactly one User, with a title and a status.
_Avoid_: Item, todo, ticket, card

**Connection**:
The link that lets a User's ChatGPT act as that User against the taskboard.
_Avoid_: Integration, install, link, session

**ChatGPT connector**:
The configuration inside ChatGPT that points at the taskboard.
_Avoid_: Plugin, app, extension
