# Atomic Red Team in the VM: official phase 1 results

*Made by `python tools/art_score.py`; detectors from `freeze-v4` (frozen: True); harness commit `f42c7f050b` (ART files committed: True); pre-registered in `docs/plans/art-prereg.md`.*

- Boots: 12; planned tests: 221; executed: 212 (clean exit: 179, with error or timeout: 33); not executed: 9 (of which never reported: 0).
- **Q1 coverage:** 132/212 = 62.3 % of executed tests detected (clean-exit tests only: 114/179 = 63.7 %).
- **Q2 without Sigma rules that cite ART:** 89/212 = 42.0 %.
- By detector family (executed tests with at least one attributed alert of that family): analystlab 1, none 80, sigma 132.
- **Q4 rules firing on the harness controls:** analystlab.new_shell_parent.

| technique | test GUID | verdict | without ART-citing rules | exit | timeout | other alerts in window | rules (level) |
|---|---|---|---|---|---|---|---|
| T1007 | 51f17016 | MISSED | MISSED | 0 |  | 1 | - |
| T1007 | 5f864a3f | MISSED | MISSED | 0 |  | 1 | - |
| T1007 | 7cd7eaa3 | MISSED | MISSED | 0 |  | 1 | - |
| T1007 | d70d82bd | DETECTED | DETECTED | 0 |  | 0 | 8f02c935-effe-45b3-8fc9-ef8696a9e41d (high) |
| T1012 | 96257079 | MISSED | MISSED | 0 |  | 1 | - |
| T1016 | 038263cb | MISSED | MISSED | 0 |  | 1 | - |
| T1016 | 7dd47911 | DETECTED | DETECTED | 0 |  | 0 | ba3f5c1b-6272-4119-9dbd-0bc8d21c2702 (high); dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium) |
| T1016 | 970ab6a1 | MISSED | MISSED | 0 |  | 1 | - |
| T1020 | 9c780d3d | DETECTED | DETECTED | 0 |  | 0 | 1139d2e2-84b1-4226-b445-354492eba8ba (medium); 1edff897-9146-48d2-9066-52e8d8f80a2f (medium); 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc (high); 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d (medium) |
| T1025 | 0b29f7e3 | DETECTED | MISSED | 0 |  | 1 | c1dda054-d638-4c16-afc8-53e007f3fbc5 (medium) |
| T1027 | 450e7218 | DETECTED | DETECTED | 0 |  | 0 | e32d4572-9826-4738-b651-95fa63747e8a (high) |
| T1027 | 8b3f4ed6 | DETECTED | DETECTED | 0 |  | 0 | d7bcd677-645d-4691-a8d4-7a5602b780d1 (high); deb9b646-a508-44ee-b7c9-d8965921c6b6 (high) |
| T1027 | a50d5a97 | DETECTED | MISSED | 0 |  | 0 | fb843269-508c-4b76-8b8d-88679db22ce7 (medium) |
| T1027.001 | a374947c | MISSED | MISSED | 0 |  | 0 | - |
| T1027.009 | 09b8f49c | DETECTED | DETECTED | 0 |  | 0 | 22e58743-4ac8-4a9f-bf19-00a0428d8c5f (high) |
| T1027.009 | 4f37ebea | DETECTED | DETECTED | 0 |  | 0 | 22e58743-4ac8-4a9f-bf19-00a0428d8c5f (high) |
| T1027.009 | 53b9902a | DETECTED | DETECTED | 0 |  | 0 | 22e58743-4ac8-4a9f-bf19-00a0428d8c5f (high) |
| T1027.009 | 75edafa4 | DETECTED | DETECTED | 0 |  | 0 | 22e58743-4ac8-4a9f-bf19-00a0428d8c5f (high) |
| T1027.009 | 8112d9ba | DETECTED | DETECTED | 0 |  | 0 | 22e58743-4ac8-4a9f-bf19-00a0428d8c5f (high); deb9b646-a508-44ee-b7c9-d8965921c6b6 (high) |
| T1027.009 | 82084e9b | DETECTED | DETECTED | 0 |  | 0 | 22e58743-4ac8-4a9f-bf19-00a0428d8c5f (high) |
| T1027.009 | a50df5f9 | MISSED | MISSED | 0 |  | 0 | - |
| T1027.009 | f989c010 | DETECTED | DETECTED | 0 |  | 0 | 22e58743-4ac8-4a9f-bf19-00a0428d8c5f (high); 7047d730-036f-4f40-b9d8-1c63e36d5e62 (medium) |
| T1027.013 | 7693ccaa | DETECTED | DETECTED | 0 | yes | 0 | e32d4572-9826-4738-b651-95fa63747e8a (high) |
| T1027.013 | b404caaa | DETECTED | DETECTED | 0 |  | 0 | 74403157-20f5-415d-89a7-c505779585cf (medium); ba3f5c1b-6272-4119-9dbd-0bc8d21c2702 (high) |
| T1027.018 | 125b1b41 | DETECTED | DETECTED | 0 |  | 1 | e312efd0-35a1-407f-8439-b8d434b438a6 (high) |
| T1027.018 | 5917f0fd | DETECTED | DETECTED | 0 |  | 1 | e312efd0-35a1-407f-8439-b8d434b438a6 (high) |
| T1033 | 1392bd0f | MISSED | MISSED | 0 |  | 0 | - |
| T1033 | 3d257a03 | DETECTED | DETECTED | 0 |  | 0 | 91edcfb1-2529-4ac2-9ecc-7617f895c7e4 (medium); c248c896-e412-4279-8c15-1c558067b6fa (medium); c30fb093-1109-4dc8-88a8-b30d11c95a5d (medium) |
| T1033 | 4c4959bf | DETECTED | DETECTED | 1 |  | 1 | c30fb093-1109-4dc8-88a8-b30d11c95a5d (medium); ccb5742c-c248-4982-8c5c-5571b9275ad3 (medium) |
| T1033 | aab580c7 | DETECTED | DETECTED | 0 |  | 1 | c248c896-e412-4279-8c15-1c558067b6fa (medium) |
| T1033 | ba38e193 | MISSED | MISSED | 1 |  | 1 | - |
| T1033 | dcb6cdee | MISSED | MISSED | 0 |  | 0 | - |
| T1036 | ba3f1b66 | DETECTED | DETECTED | 0 |  | 0 | 1cf465a1-2609-4c15-9b66-c32dbe4bfd67 (high); b447f7de-1e53-4cbf-bfb4-f1f6d0b04e4e (high); e7be6119-fc37-43f0-ad4f-1f3f99be2f9f (high); f0540f7e-2db3-4432-b9e0-3965486744bc (high) |
| T1036.002 | d7c03c7e | DETECTED | DETECTED | -1 | yes | 3 | 602a1f13-c640-4d73-b053-be9a2fa58b96 (high); 7047d730-036f-4f40-b9d8-1c63e36d5e62 (medium); 979baf41-ca44-4540-9d0c-4fcef3b5a3a4 (high); b5522a23-82da-44e5-9c8b-e10ed8955f88 (medium); e312efd0-35a1-407f-8439-b8d434b438a6 (high) |
| T1036.003 | 3a2a578b | DETECTED | DETECTED | 1 |  | 1 | 0ba1da6d-b6ce-4366-828c-18826c9de23e (high); f5d19838-41b5-476c-98d8-ba8af4929ee2 (high) |
| T1036.003 | 5ba5a3d1 | DETECTED | DETECTED | -1 | yes | 1 | 36480ae1-a1cb-4eaa-a0d6-29801d7e9142 (medium); d5866ddf-ce8f-4aea-b28e-d96485a20d3d (medium); e4a6b256-3e47-40fc-89d2-7a477edd6915 (high) |
| T1036.003 | ac9d0fc3 | DETECTED | DETECTED | -1 | yes | 1 | 0ba1da6d-b6ce-4366-828c-18826c9de23e (high); 1027d292-dd87-4a1a-8701-2abe04d7783c (medium); d5866ddf-ce8f-4aea-b28e-d96485a20d3d (medium); e4a6b256-3e47-40fc-89d2-7a477edd6915 (high) |
| T1036.005 | 35eb8d16 | DETECTED | DETECTED | 0 |  | 0 | 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d (medium); cbb9e3d1-2386-4e59-912e-62f1484f7a89 (medium); d5866ddf-ce8f-4aea-b28e-d96485a20d3d (medium); dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium); e4a6b256-3e47-40fc-89d2-7a477edd6915 (high); f17211f1-1f24-4d0c-829f-31e28dc93cdd (high) |
| T1037.001 | d6042746 | DETECTED | DETECTED | 0 |  | 3 | 21d856f9-9281-4ded-9377-51a1a6e2a432 (high); 966315ef-c5e1-4767-ba25-fce9c8de3660 (high); 9ace0707-b560-49b8-b6ca-5148b42f39fb (medium); f59c3faf-50f3-464b-9f4c-1b67ab512d99 (medium) |
| T1041 | d1253f6e | DETECTED | DETECTED | 0 |  | 0 | 1139d2e2-84b1-4226-b445-354492eba8ba (medium); 7d1aaf3d-4304-425c-b7c3-162055e0b3ab (high); 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d (medium) |
| T1048.003 | 6aa58451 | DETECTED | DETECTED | 0 |  | 0 | 1139d2e2-84b1-4226-b445-354492eba8ba (medium); 1edff897-9146-48d2-9066-52e8d8f80a2f (medium); 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc (high); 7d1aaf3d-4304-425c-b7c3-162055e0b3ab (high); 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d (medium) |
| T1048.003 | dd4b4421 | DETECTED | MISSED | 0 |  | 0 | 4c4af3cd-2115-479c-8193-6b8bfce9001c (medium) |
| T1049 | b52c8233 | MISSED | MISSED | 0 |  | 0 | - |
| T1049 | f069f0f1 | MISSED | MISSED | 0 |  | 0 | - |
| T1053.002 | 4a6c0dc4 | DETECTED | MISSED | 1 |  | 1 | 60fc936d-2eb0-4543-8a13-911c750a1dfc (high) |
| T1053.005 | 1a73e89e | DETECTED | DETECTED | 0 |  | 0 | 7047d730-036f-4f40-b9d8-1c63e36d5e62 (medium); dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium) |
| T1053.005 | 42f53695 | DETECTED | DETECTED | 0 |  | 1 | 24c8392b-aa3c-46b7-a545-43f71657fe98 (high) |
| T1053.005 | af9fd58f | DETECTED | MISSED | 0 |  | 1 | 363eccc0-279a-4ccf-a3ab-24c2e63b11fb (medium) |
| T1053.005 | dda6fc7b | DETECTED | MISSED | 0 |  | 1 | 363eccc0-279a-4ccf-a3ab-24c2e63b11fb (medium) |
| T1053.005 | e895677d | DETECTED | DETECTED | 0 |  | 1 | 536e2947-3729-478c-9903-745aaffe60d2 (medium); c4eeeeae-89f4-43a7-8b48-8d1bdfa66c78 (high); e32d4572-9826-4738-b651-95fa63747e8a (high); f2c64357-b1d2-41b7-849f-34d2682c0fad (high) |
| T1057 | 11ba69ee | DETECTED | DETECTED | 0 |  | 1 | ccb5742c-c248-4982-8c5c-5571b9275ad3 (medium); fe63010f-8823-4864-a96b-a7b4a0f7b929 (high) |
| T1057 | 3b3809b6 | MISSED | MISSED | 0 |  | 0 | - |
| T1057 | 4fd35378 | MISSED | MISSED | -2147467260 |  | 1 | - |
| T1057 | 668f1d74 | DETECTED | DETECTED | 0 |  | 0 | ba3f5c1b-6272-4119-9dbd-0bc8d21c2702 (high); dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium); f62176f3-8128-4faa-bf6c-83261322e5eb (medium) |
| T1057 | b51239b4 | MISSED | MISSED | 0 |  | 2 | - |
| T1057 | c5806a4f | MISSED | MISSED | 0 |  | 1 | - |
| T1059.003 | 127b4afe | MISSED | MISSED | 0 |  | 1 | - |
| T1059.003 | d0eb3597 | MISSED | MISSED | 0 |  | 1 | - |
| T1069.001 | 1f454dd6 | MISSED | MISSED | 0 |  | 1 | - |
| T1069.001 | 69119e58 | MISSED | MISSED | 0 |  | 0 | - |
| T1069.001 | a580462d | MISSED | MISSED | 0 |  | 0 | - |
| T1070.003 | 1d0d9aa6 | MISSED | MISSED | 0 |  | 0 | - |
| T1070.003 | 22c779cd | DETECTED | DETECTED | 0 |  | 0 | bde47d4b-9987-405c-94c7-b080410e8ea7 (high) |
| T1070.003 | 2f898b81 | DETECTED | DETECTED | 0 |  | 0 | 26b692dc-1722-49b2-b496-a8258aa6371d (medium) |
| T1070.003 | da75ae8d | DETECTED | DETECTED | 0 |  | 0 | 26b692dc-1722-49b2-b496-a8258aa6371d (medium); bde47d4b-9987-405c-94c7-b080410e8ea7 (high); f4ff7323-b5fc-4323-8b52-6b9408e15788 (medium) |
| T1070.004 | 861ea0b4 | MISSED | MISSED | 0 |  | 1 | - |
| T1070.004 | 9dee89bd | MISSED | MISSED | 0 |  | 0 | - |
| T1070.004 | ded937c4 | MISSED | MISSED | 0 |  | 1 | - |
| T1070.004 | edd779e4 | MISSED | MISSED | 0 |  | 0 | - |
| T1070.005 | 0512d214 | DETECTED | MISSED | 0 |  | 0 | 66a4d409-451b-4151-94f4-a55d559c49b0 (medium) |
| T1070.005 | 09210ad5 | MISSED | MISSED | 2 |  | 1 | - |
| T1071.001 | 81c13829 | NOT EXECUTED | NOT EXECUTED | None | yes | 0 | - |
| T1082 | 224b4daf | MISSED | MISSED | 0 |  | 1 | - |
| T1082 | 66703791 | DETECTED | MISSED | 0 |  | 1 | 970007b7-ce32-49d0-a4a4-fbef016950bd (medium) |
| T1082 | 70e13ef4 | MISSED | MISSED | 0 |  | 0 | - |
| T1082 | 85cfbf23 | MISSED | MISSED | 0 |  | 1 | - |
| T1082 | 96be6002 | MISSED | MISSED | 0 |  | 1 | - |
| T1082 | acfcd709 | MISSED | MISSED | 0 |  | 1 | - |
| T1082 | be3b5fe3 | MISSED | MISSED | 0 |  | 1 | - |
| T1082 | c187c9bc | MISSED | MISSED | 0 |  | 1 | - |
| T1082 | ce479c1a | MISSED | MISSED | 0 |  | 2 | - |
| T1082 | f2f91612 | MISSED | MISSED | 1 |  | 1 | - |
| T1082 | f400d1c0 | MISSED | MISSED | 0 |  | 1 | - |
| T1082 | f6ecb109 | MISSED | MISSED | 0 |  | 1 | - |
| T1083 | 0e36303b | MISSED | MISSED | -1 | yes | 1 | - |
| T1083 | 2158908e | MISSED | MISSED | 0 |  | 0 | - |
| T1083 | c6c34f61 | DETECTED | MISSED | 0 |  | 0 | 162e69a7-7981-4344-84a9-0f1c9a217a52 (medium) |
| T1087.001 | 80887bec | DETECTED | MISSED | 0 |  | 1 | 07f8bdc2-c9b3-472a-9817-5a670b872f53 (high) |
| T1087.001 | a138085e | MISSED | MISSED | 1 |  | 1 | - |
| T1087.001 | ae4b6361 | DETECTED | MISSED | 0 |  | 0 | 07f8bdc2-c9b3-472a-9817-5a670b872f53 (high); 4fdc44df-bfe9-4fcc-b041-68f5a2d3031c (medium) |
| T1095 | b2858526 | DETECTED | MISSED | 0 |  | 0 | dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium) |
| T1105 | 1a02df58 | DETECTED | MISSED | 0 |  | 0 | 863218bd-c7d0-4c52-80cd-0a96c09f54af (high); 8d7e392e-9b28-49e1-831d-5949c6281228 (high) |
| T1105 | 42dc4460 | DETECTED | DETECTED | 0 |  | 0 | 3b6ab547-8ec2-4991-b9d2-2b06702a48d7 (medium); 403c2cc0-7f6b-4925-9423-bfa573bed7eb (medium) |
| T1105 | 54a4daf1 | DETECTED | DETECTED | 0 |  | 0 | 3b6ab547-8ec2-4991-b9d2-2b06702a48d7 (medium) |
| T1105 | 5f507e45 | DETECTED | DETECTED | 0 |  | 1 | af491bca-e752-4b44-9c86-df5680533dbc (high); c082c2b0-525b-4dbc-9a26-a57dc4692074 (high) |
| T1105 | 6fdaae87 | DETECTED | DETECTED | -1 | yes | 1 | 4480827a-9799-4232-b2c4-ccc6c4e9e12b (high) |
| T1105 | a1921cd3 | DETECTED | DETECTED | -2145844844 |  | 1 | 2ddef153-167b-4e89-86b6-757a9e65dcac (high); 5b80a791-ad9b-4b75-bcc1-ad4e1e89c200 (high); 99c840f2-2012-46fd-9141-c761987550ef (high); d059842b-6b9d-4ed1-b5c3-5b89143c6ede (medium) |
| T1105 | dd3b61dd | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1105 | ffd492e3 | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1112 | 09147b61 | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | 1324796b | DETECTED | MISSED | 0 |  | 2 | 5df86130-4e95-4a54-90f7-26541b40aec2 (medium) |
| T1112 | 15f44ea9 | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | 4b81bcfa | DETECTED | MISSED | 1 |  | 1 | 3f6b7b62-61aa-45db-96bd-9c31b36b653c (high) |
| T1112 | 61d35188 | DETECTED | MISSED | 1 |  | 1 | 3f6b7b62-61aa-45db-96bd-9c31b36b653c (high) |
| T1112 | 65704cd4 | DETECTED | DETECTED | 0 |  | 1 | 02ee49e2-e294-4d0f-9278-f5b3212fc588 (high); 20f0ee37-5942-4e45-b7d5-c5b5db9df5cd (medium); 24357373-078f-44ed-9ac4-6d334a668a11 (medium); de587dce-915e-4218-aac4-835ca6af6f70 (medium) |
| T1112 | 795d3248 | DETECTED | MISSED | 0 |  | 1 | 5a93eb65-dffa-4543-b761-94aa60098fb6 (medium) |
| T1112 | 7e7b62e9 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | b1a4d687 | DETECTED | DETECTED | 0 |  | 0 | 10344bb3-7f65-46c2-b915-2d00d47be5b0 (high) |
| T1112 | b6a03947 | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | c26fb85a | MISSED | MISSED | 1 |  | 1 | - |
| T1112 | c375558d | DETECTED | MISSED | 0 |  | 0 | b7e2a8d4-74bb-4b78-adc9-3f92af2d4829 (high) |
| T1112 | c88ef166 | DETECTED | DETECTED | 0 |  | 1 | 10344bb3-7f65-46c2-b915-2d00d47be5b0 (high); 3fd4c8d7-8362-4557-a8e6-83b29cc0d724 (high) |
| T1112 | ca8ba39c | MISSED | MISSED | 1 |  | 1 | - |
| T1112 | cf447677 | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | f3a6cceb | DETECTED | DETECTED | 0 |  | 0 | 61d0475c-173f-4844-86f7-f3eebae1c66b (medium); 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180 (medium) |
| T1112 | ffeddced | MISSED | MISSED | 1 |  | 1 | - |
| T1113 | e9313014 | DETECTED | MISSED | 0 |  | 0 | d4a11f63-2390-411c-9adf-d791fd152830 (medium) |
| T1115 | 0cd14633 | DETECTED | MISSED | 0 |  | 1 | 241e802a-b65e-484f-88cd-c2dc10f9206d (medium) |
| T1115 | d6dc21af | DETECTED | DETECTED | 0 |  | 2 | b9aeac14-2ffd-4ad3-b967-1354a4e628c3 (medium) |
| T1119 | 634bd9b9 | DETECTED | MISSED | 0 |  | 0 | c1dda054-d638-4c16-afc8-53e007f3fbc5 (medium) |
| T1119 | aa1180e2 | DETECTED | MISSED | 0 |  | 1 | aa2efee7-34dd-446e-8a37-40790a66efd7 (medium) |
| T1119 | c3f6d794 | DETECTED | MISSED | 0 |  | 0 | a9723fcc-881c-424c-8709-fd61442ab3c3 (medium) |
| T1119 | cb379146 | DETECTED | MISSED | 0 | yes | 1 | f576a613-2392-4067-9d1a-9345fb58d8d1 (medium) |
| T1120 | 2cb4dbf2 | MISSED | MISSED | 0 |  | 0 | - |
| T1120 | 424e18fd | MISSED | MISSED | 0 |  | 1 | - |
| T1120 | 5c876daf | MISSED | MISSED | 0 |  | 0 | - |
| T1123 | 7a21cce2 | DETECTED | DETECTED | 1 |  | 2 | 62120148-6b7a-42be-8b91-271c04e281a3 (high) |
| T1124 | 1d5711d6 | MISSED | MISSED | 0 |  | 0 | - |
| T1124 | 20aba24b | MISSED | MISSED | 0 |  | 1 | - |
| T1124 | 25c5d1f1 | MISSED | MISSED | 0 |  | 1 | - |
| T1124 | d5d5a6b0 | DETECTED | MISSED | 0 |  | 1 | 6da2c9f5-7c53-401b-aacb-92c040ce1215 (high) |
| T1132.001 | c3ed6d2a | DETECTED | DETECTED | 0 |  | 0 | 1139d2e2-84b1-4226-b445-354492eba8ba (medium); 7d1aaf3d-4304-425c-b7c3-162055e0b3ab (high); 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d (medium); bb780e0c-16cf-4383-8383-1e5471db6cf9 (medium) |
| T1135 | 13daa2cf | MISSED | MISSED | 1 |  | 1 | - |
| T1135 | 1b0814d1 | MISSED | MISSED | 0 |  | 0 | - |
| T1135 | 20f1097d | MISSED | MISSED | 0 |  | 1 | - |
| T1135 | ab39a04f | MISSED | MISSED | 0 |  | 1 | - |
| T1140 | 71abc534 | DETECTED | DETECTED | 0 |  | 1 | 0ba1da6d-b6ce-4366-828c-18826c9de23e (high); 737e618a-a410-49b5-bec3-9e55ff7fbc15 (high); 82a6714f-4899-4f16-9c1e-9a333544d4c3 (high); e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a (medium); ea0cdc3e-2239-4f26-a947-4e8f8224e464 (high); f5d19838-41b5-476c-98d8-ba8af4929ee2 (high); fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1140 | 9f8b1c54 | DETECTED | DETECTED | 0 |  | 1 | 9f107a84-532c-41af-b005-8d12a607639f (medium) |
| T1140 | dc6fe391 | DETECTED | DETECTED | 0 |  | 1 | 1cf465a1-2609-4c15-9b66-c32dbe4bfd67 (high); 737e618a-a410-49b5-bec3-9e55ff7fbc15 (high); 82a6714f-4899-4f16-9c1e-9a333544d4c3 (high); cc9cbe82-7bc0-4ef5-bc23-bbfb83947be7 (high); e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a (medium); f0540f7e-2db3-4432-b9e0-3965486744bc (high) |
| T1187 | 81cfdd7f | DETECTED | DETECTED | 0 |  | 0 | 93671f99-04eb-4ab4-a161-70d446a84003 (medium); fb843269-508c-4b76-8b8d-88679db22ce7 (medium) |
| T1197 | 3c73d728 | DETECTED | DETECTED | -2145844844 |  | 1 | 2ddef153-167b-4e89-86b6-757a9e65dcac (high); 5b80a791-ad9b-4b75-bcc1-ad4e1e89c200 (high); 99c840f2-2012-46fd-9141-c761987550ef (high); d059842b-6b9d-4ed1-b5c3-5b89143c6ede (medium) |
| T1197 | 62a06ec5 | DETECTED | DETECTED | 0 |  | 2 | 2ddef153-167b-4e89-86b6-757a9e65dcac (high); 5b80a791-ad9b-4b75-bcc1-ad4e1e89c200 (high); 99c840f2-2012-46fd-9141-c761987550ef (high); analystlab.ping_delay_chained (medium); b9cbbc17-d00d-4e3d-a827-b06d03d2380d (medium); d059842b-6b9d-4ed1-b5c3-5b89143c6ede (medium) |
| T1197 | afb5e09e | DETECTED | DETECTED | -1 |  | 1 | bb58aa4a-b80b-415a-a2c0-2f65a4c81009 (high) |
| T1197 | f63b8bc4 | DETECTED | DETECTED | 0 |  | 0 | 1139d2e2-84b1-4226-b445-354492eba8ba (medium); 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d (medium); dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium) |
| T1202 | 0fd14730 | DETECTED | DETECTED | 0 |  | 0 | 64760eef-87f7-4ed3-93fd-655668ea9420 (medium) |
| T1202 | 8b34a448 | DETECTED | DETECTED | 0 |  | 1 | 9aa5106d-bce3-4b13-86df-3a20f1d5cf0b (medium) |
| T1202 | cecfea7a | DETECTED | DETECTED | 0 |  | 1 | 0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2 (medium) |
| T1202 | cf3391e0 | DETECTED | DETECTED | 0 |  | 1 | 7dc2dedd-7603-461a-bc13-15803d132355 (medium) |
| T1204.002 | 3f3120f0 | MISSED | MISSED | 0 |  | 0 | - |
| T1204.002 | 3f3af983 | DETECTED | DETECTED | 1 |  | 1 | 08249dc0-a28d-4555-8ba5-9255a198e08c (medium); 1228c958-e64e-4e71-92ad-7d429f4138ba (high); cea72823-df4d-4567-950c-0b579eaf0846 (medium) |
| T1216 | 2a8f2d3c | DETECTED | DETECTED | 0 |  | 1 | 737e618a-a410-49b5-bec3-9e55ff7fbc15 (high); c363385c-f75d-4753-a108-c1a8e28bdbda (high) |
| T1216.001 | 9dd29a1f | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1216.002 | 275d963d | DETECTED | DETECTED | 0 |  | 1 | 36475a7d-0f6d-4dce-9b01-6aeb473bbaf1 (medium); 95eadcb2-92e4-4ed1-9031-92547773a6db (medium) |
| T1217 | 4312cdbc | MISSED | MISSED | 1 |  | 1 | - |
| T1217 | 727dbcdb | MISSED | MISSED | 0 |  | 1 | - |
| T1217 | 76f71e2f | MISSED | MISSED | 1 |  | 1 | - |
| T1217 | faab755e | MISSED | MISSED | 0 |  | 0 | - |
| T1218 | 5bcda9cd | DETECTED | DETECTED | 0 |  | 1 | 1e59c230-6670-45bf-83b0-98903780607e (medium) |
| T1218 | 7816c252 | DETECTED | DETECTED | 0 |  | 0 | 9cfc00b6-bfb7-49ce-9781-ef78503154bb (medium) |
| T1218 | ab76e34f | DETECTED | DETECTED | 0 |  | 1 | 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25 (high); 7021255e-5db3-4946-a8b9-0ba7a4644a69 (high) |
| T1218 | f8da74bb | DETECTED | DETECTED | 0 |  | 1 | 1e59c230-6670-45bf-83b0-98903780607e (medium) |
| T1218.005 | 8707a805 | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1218.010 | c9d0c4ef | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1218.011 | 32d1cf1b | DETECTED | DETECTED | 0 |  | 1 | 2c28c248-7f50-417a-9186-a85b223010ee (medium); 4782eb5a-a513-4523-a0ac-f3082b26ac5c (high); c3a99af4-35a9-4668-879e-c09aeb4f2bdf (medium) |
| T1218.011 | 638730e7 | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1218.011 | 8a7f56ee | DETECTED | DETECTED | 0 |  | 0 | 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf (medium); e593cf51-88db-4ee1-b920-37e89012a3c9 (medium) |
| T1218.011 | 9f5d081a | DETECTED | DETECTED | 0 |  | 1 | 9386d78a-7207-4048-9c9f-a93a7c2d1c05 (medium); e593cf51-88db-4ee1-b920-37e89012a3c9 (medium) |
| T1218.011 | f3ad3c5b | DETECTED | DETECTED | 0 |  | 1 | e593cf51-88db-4ee1-b920-37e89012a3c9 (medium) |
| T1222.001 | 32b979da | DETECTED | DETECTED | 0 |  | 1 | 4281cb20-2994-4580-aa63-c8b86d019934 (medium) |
| T1222.001 | 98d34bb4 | DETECTED | MISSED | 0 |  | 1 | 554601fb-9b71-4bcc-abf4-21a611be4fde (medium) |
| T1222.001 | a8206bcc | MISSED | MISSED | 0 | yes | 3 | - |
| T1222.001 | bec1e95c | MISSED | MISSED | 0 |  | 1 | - |
| T1496 | 44315fb0 | MISSED | MISSED | 0 |  | 0 | - |
| T1497.001 | 4a41089a | DETECTED | MISSED | 0 |  | 0 | d93129cd-1ee0-479f-bc03-ca6f129882e3 (medium) |
| T1497.001 | 502a7dc4 | DETECTED | MISSED | 0 |  | 0 | d93129cd-1ee0-479f-bc03-ca6f129882e3 (medium) |
| T1497.001 | eed8b13f | DETECTED | MISSED | 0 |  | 0 | dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium) |
| T1518 | 68981660 | DETECTED | MISSED | 0 |  | 1 | e13f668e-7f95-443d-98d2-1816a7648a7b (medium) |
| T1518 | c49978f6 | DETECTED | MISSED | 0 |  | 0 | 2650dd1a-eb2a-412d-ac36-83f06c4f2282 (medium) |
| T1518.001 | 7f566051 | DETECTED | MISSED | 0 |  | 0 | 904e8e61-8edf-4350-b59c-b905fc8e810c (medium) |
| T1518.001 | f92a380f | DETECTED | MISSED | 0 |  | 1 | 4fe074b4-b833-4081-8f24-7dcfeca72b42 (medium); ccb5742c-c248-4982-8c5c-5571b9275ad3 (medium) |
| T1547 | 5cb0b071 | DETECTED | DETECTED | 0 |  | 0 | a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1 (medium) |
| T1547 | cb01b3da | DETECTED | DETECTED | 0 |  | 1 | a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1 (medium) |
| T1547.001 | 8834b65a | DETECTED | DETECTED | 0 |  | 1 | 855bc8b5-2ae8-402e-a9ed-b889e6df1900 (medium); 8f3ab69a-aa22-4943-aa58-e0a52fdf6818 (high); 9c226817-8dc9-46c2-a58d-66655aafd7dc (high); f5d19838-41b5-476c-98d8-ba8af4929ee2 (high) |
| T1547.001 | 9dc7767b | DETECTED | DETECTED | 0 |  | 0 | 20f0ee37-5942-4e45-b7d5-c5b5db9df5cd (medium); 313fbb0a-a341-4682-848d-6d6f8c4fab7c (medium); 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180 (medium); 8d85cf08-bf97-4260-ba49-986a2a65129c (medium) |
| T1547.001 | bda6a3d6 | DETECTED | DETECTED | 1 |  | 1 | 277efb8f-60be-4f10-b4d3-037802f37167 (high) |
| T1547.001 | e55be3fd | DETECTED | DETECTED | 0 |  | 1 | 20f0ee37-5942-4e45-b7d5-c5b5db9df5cd (medium); 24357373-078f-44ed-9ac4-6d334a668a11 (medium); de587dce-915e-4218-aac4-835ca6af6f70 (medium) |
| T1547.004 | 95a3c42f | DETECTED | MISSED | 0 |  | 0 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium) |
| T1547.004 | bf9f9d65 | DETECTED | MISSED | 0 |  | 0 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium) |
| T1547.004 | d40da266 | DETECTED | DETECTED | 0 |  | 0 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium); a6a39bdb-935c-4f0a-ab77-35f4bbf44d33 (medium) |
| T1547.004 | f9b8daff | DETECTED | MISSED | 0 |  | 0 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium) |
| T1547.004 | fb32c935 | DETECTED | MISSED | 0 |  | 0 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium) |
| T1547.009 | ce4fc678 | DETECTED | DETECTED | 0 |  | 1 | 737e618a-a410-49b5-bec3-9e55ff7fbc15 (high) |
| T1548.002 | 350b8e4b | NOT EXECUTED | NOT EXECUTED | None | yes | 0 | - |
| T1548.002 | 3b96673f | MISSED | MISSED | 0 |  | 0 | - |
| T1548.002 | 3be891eb | MISSED | MISSED | 0 |  | 0 | - |
| T1548.002 | 3c51abf2 | DETECTED | DETECTED | 0 |  | 0 | dd3ee8cc-f751-41c9-ba53-5a32ed47e563 (medium) |
| T1548.002 | 3f627297 | DETECTED | DETECTED | 0 |  | 0 | dd3ee8cc-f751-41c9-ba53-5a32ed47e563 (medium) |
| T1548.002 | 5073adf8 | DETECTED | MISSED | -1 | yes | 3 | 674202d0-b22a-4af4-ae5f-2eda1f3da1af (high) |
| T1548.002 | 58f641ea | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1548.002 | a6ce9acf | MISSED | MISSED | 0 |  | 0 | - |
| T1548.002 | b6f4645c | MISSED | MISSED | 1 |  | 1 | - |
| T1559 | 17521690 | MISSED | MISSED | 0 |  | 0 | - |
| T1560 | 41410c60 | MISSED | MISSED | 0 |  | 0 | - |
| T1560.001 | 2a7bc405 | MISSED | MISSED | 1 |  | 1 | - |
| T1564.003 | f151ee37 | DETECTED | MISSED | 0 |  | 0 | 313fbb0a-a341-4682-848d-6d6f8c4fab7c (medium) |
| T1564.004 | 0045ea16 | DETECTED | MISSED | 0 |  | 0 | 8c521530-5169-495d-a199-0a3a881ad24e (high) |
| T1564.004 | 17e7637a | MISSED | MISSED | 0 |  | 1 | - |
| T1564.004 | 2ab75061 | DETECTED | MISSED | 0 |  | 0 | a699b30e-d010-46c8-bbd1-ee2e26765fe9 (medium) |
| T1564.004 | 3e6791e7 | DETECTED | MISSED | 0 |  | 2 | 0900463c-b33b-49a8-be1d-552a3b553dae (medium) |
| T1566.002 | bc177ef9 | DETECTED | DETECTED | 0 |  | 4 | 36210e0d-5b19-485d-a087-c096088885f0 (high); dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium); fb843269-508c-4b76-8b8d-88679db22ce7 (medium) |
| T1567.004 | f0057c81 | DETECTED | DETECTED | 0 |  | 0 | 1139d2e2-84b1-4226-b445-354492eba8ba (medium); 1edff897-9146-48d2-9066-52e8d8f80a2f (medium); 7d1aaf3d-4304-425c-b7c3-162055e0b3ab (high); 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d (medium) |
| T1572 | ae9ef4b0 | DETECTED | DETECTED | 0 |  | 0 | 1139d2e2-84b1-4226-b445-354492eba8ba (medium); 1edff897-9146-48d2-9066-52e8d8f80a2f (medium); 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d (medium) |
| T1574.011 | f7536d63 | DETECTED | MISSED | 0 |  | 0 | 95afc12e-3cbb-40c3-9340-84a032e596a3 (medium) |
| T1614.001 | 1f23bfe8 | MISSED | MISSED | 0 |  | 0 | - |
| T1614.001 | 631d4cf1 | DETECTED | DETECTED | 0 |  | 1 | c43a5405-e8e1-4221-9ac9-dbe3fa14e886 (medium) |
| T1614.001 | d91473ca | DETECTED | DETECTED | 0 |  | 1 | 7090adee-82e2-4269-bd59-80691e7c6338 (medium) |
| T1649 | eb121494 | DETECTED | DETECTED | 0 |  | 0 | 9e716b33-63b2-46da-86a4-bd3c3b9b5dfb (medium); aa7a3fce-bef5-4311-9cc1-5f04bb8c308c (medium) |
| T1652 | 235b30a2 | DETECTED | DETECTED | 0 |  | 0 | a20def93-0709-4eae-9bd2-31206e21e6b2 (medium) |
| T1654 | fef0ace1 | MISSED | MISSED | 0 |  | 1 | - |
| T1680 | 3a4d51bd | MISSED | MISSED | 0 |  | 0 | - |
| T1685 | 0486ee68 | MISSED | MISSED | 0 |  | 0 | - |
