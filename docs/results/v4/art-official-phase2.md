# Atomic Red Team in the VM: official phase 2 results

*Made by `python tools/art_score.py`; detectors from `freeze-v4` (frozen: True); harness commit `f42c7f050b` (ART files committed: True); pre-registered in `docs/plans/art-prereg.md`.*

- Boots: 10; planned tests: 151; executed: 150 (clean exit: 142, with error or timeout: 8); not executed: 1 (of which never reported: 0).
- **Q1 coverage:** 94/150 = 62.7 % of executed tests detected (clean-exit tests only: 92/142 = 64.8 %).
- **Q2 without Sigma rules that cite ART:** 64/150 = 42.7 %.
- By detector family (executed tests with at least one attributed alert of that family): none 56, sigma 94.
- **Q4 rules firing on the harness controls:** analystlab.new_shell_parent.

| technique | test GUID | verdict | without ART-citing rules | exit | timeout | other alerts in window | rules (level) |
|---|---|---|---|---|---|---|---|
| T1006 | 88f6327e | DETECTED | MISSED | 0 |  | 0 | 70ad982f-67c8-40e0-a955-b920c2fa05cb (medium) |
| T1007 | 89676ba1 | MISSED | MISSED | 0 |  | 1 | - |
| T1012 | 0434d081 | MISSED | MISSED | 0 |  | 0 | - |
| T1012 | 5c784969 | MISSED | MISSED | 1 |  | 1 | - |
| T1012 | 6fb4c4c5 | MISSED | MISSED | 1 |  | 1 | - |
| T1012 | 8f7578c4 | DETECTED | MISSED | 1 |  | 1 | 970007b7-ce32-49d0-a4a4-fbef016950bd (medium); b7e2a8d4-74bb-4b78-adc9-3f92af2d4829 (high) |
| T1027 | 7e47ee60 | MISSED | MISSED | 0 |  | 0 | - |
| T1027.013 | 6e8dea32 | MISSED | MISSED | 0 |  | 0 | - |
| T1036.003 | 83810c46 | DETECTED | DETECTED | 0 |  | 1 | 36480ae1-a1cb-4eaa-a0d6-29801d7e9142 (medium); d5866ddf-ce8f-4aea-b28e-d96485a20d3d (medium); e4a6b256-3e47-40fc-89d2-7a477edd6915 (high); fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1036.004 | f9f2fe59 | DETECTED | DETECTED | 0 |  | 1 | 89ca78fd-b37c-4310-b3d3-81a023f83936 (high); f2c64357-b1d2-41b7-849f-34d2682c0fad (high) |
| T1039 | 6ed67921 | DETECTED | DETECTED | 0 |  | 1 | 855bc8b5-2ae8-402e-a9ed-b889e6df1900 (medium) |
| T1053.005 | 02124c37 | DETECTED | DETECTED | 0 |  | 0 | 674202d0-b22a-4af4-ae5f-2eda1f3da1af (high); 7a02e22e-b885-4404-b38b-1ddc7e65258a (medium) |
| T1053.005 | 6731e8a0 | DETECTED | DETECTED | 0 |  | 1 | 24c8392b-aa3c-46b7-a545-43f71657fe98 (high); 81325ce1-be01-4250-944f-b4789644556f (medium); f2c64357-b1d2-41b7-849f-34d2682c0fad (high) |
| T1053.005 | 8fcfa3d5 | DETECTED | DETECTED | 0 |  | 2 | 674202d0-b22a-4af4-ae5f-2eda1f3da1af (high); 7a02e22e-b885-4404-b38b-1ddc7e65258a (medium) |
| T1053.005 | fec27f65 | DETECTED | DETECTED | 0 |  | 1 | 24c8392b-aa3c-46b7-a545-43f71657fe98 (high); 7a02e22e-b885-4404-b38b-1ddc7e65258a (medium); 89ca78fd-b37c-4310-b3d3-81a023f83936 (high); f2c64357-b1d2-41b7-849f-34d2682c0fad (high) |
| T1059.003 | 00682c9f | DETECTED | DETECTED | 0 |  | 1 | 1228c958-e64e-4e71-92ad-7d429f4138ba (high); 8de1cbe8-d6f5-496d-8237-5f44a721c7a0 (medium); c30fb093-1109-4dc8-88a8-b30d11c95a5d (medium); cea72823-df4d-4567-950c-0b579eaf0846 (medium) |
| T1070.004 | 36f96049 | MISSED | MISSED | 0 |  | 0 | - |
| T1070.004 | f723d13d | MISSED | MISSED | 0 |  | 1 | - |
| T1070.005 | 99c657aa | DETECTED | MISSED | 0 |  | 3 | c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e (medium) |
| T1070.008 | d29f01ea | MISSED | MISSED | 0 |  | 0 | - |
| T1070.008 | edddff85 | MISSED | MISSED | 0 |  | 0 | - |
| T1078.001 | aa6cb8c4 | DETECTED | DETECTED | 0 |  | 3 | 5b768e71-86f2-4879-b448-81061cbae951 (high) |
| T1078.003 | a524ce99 | DETECTED | DETECTED | 0 |  | 3 | ad720b90-25ad-43ff-9b5e-5c841facc8e5 (medium); cd219ff3-fa99-45d4-8380-a7d15116c6dc (medium) |
| T1082 | 7161b085 | MISSED | MISSED | 1 |  | 1 | - |
| T1098 | 5598f7cb | DETECTED | DETECTED | 0 |  | 1 | 4fdc44df-bfe9-4fcc-b041-68f5a2d3031c (medium); c8a180d6-47a3-4345-a609-53f9c3d834fc (medium) |
| T1105 | 2ca61766 | DETECTED | DETECTED | 0 |  | 1 | d4ca7c59-e9e4-42d8-bf57-91a776efcb87 (medium) |
| T1105 | fa5a2759 | DETECTED | DETECTED | 0 |  | 1 | 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d (medium); 36480ae1-a1cb-4eaa-a0d6-29801d7e9142 (medium); 855bc8b5-2ae8-402e-a9ed-b889e6df1900 (medium); be58d2e2-06c8-4f58-b666-b99f6dc3b6cd (high); d5866ddf-ce8f-4aea-b28e-d96485a20d3d (medium); e4a6b256-3e47-40fc-89d2-7a477edd6915 (high); f17211f1-1f24-4d0c-829f-31e28dc93cdd (high); fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1112 | 003f466a | DETECTED | DETECTED | 0 |  | 1 | e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | 01b20ca8 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 02d8b9f7 | DETECTED | DETECTED | 0 |  | 1 | 0e0255bf-2548-47b8-9582-c0955c9283f5 (high) |
| T1112 | 0b79c06f | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | 10b33fb0 | DETECTED | DETECTED | 0 |  | 1 | 0e0255bf-2548-47b8-9582-c0955c9283f5 (high) |
| T1112 | 12f50e15 | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | 20fc9daa | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | 26fc7375 | DETECTED | DETECTED | 0 |  | 1 | 0e0255bf-2548-47b8-9582-c0955c9283f5 (high) |
| T1112 | 3235aafe | DETECTED | DETECTED | 0 |  | 2 | 8fbe98a8-8f9d-44f8-aa71-8c572e29ef06 (high) |
| T1112 | 335a6b15 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 3448824b | NOT EXECUTED | NOT EXECUTED | None |  | 0 | - |
| T1112 | 35727d9e | DETECTED | DETECTED | 0 |  | 1 | 0d5675be-bc88-4172-86d3-1e96a4476536 (high); a2863fbc-d5cb-48d5-83fb-d976d4b1743b (medium) |
| T1112 | 37950714 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 396f997b | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 39f1f378 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 3ac0b30f | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 3e757ce7 | DETECTED | DETECTED | 0 |  | 1 | 5a93eb65-dffa-4543-b761-94aa60098fb6 (medium); ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | 4469192c | DETECTED | DETECTED | 0 |  | 1 | 73a883d0-0348-4be4-a8d8-51031c2564f8 (high) |
| T1112 | 45914594 | DETECTED | MISSED | 0 |  | 1 | 3ae1a046-f7db-439d-b7ce-b8b366b81fa6 (medium) |
| T1112 | 4c4bf587 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 4d72d4b1 | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | 4f4e2f9f | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 599f3b5c | DETECTED | DETECTED | 0 |  | 2 | 8fbe98a8-8f9d-44f8-aa71-8c572e29ef06 (high) |
| T1112 | 5e27bdb4 | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | 68254a85 | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | 71db768a | DETECTED | MISSED | 0 |  | 1 | 275641a5-a492-45e2-a817-7c81e9d9d3e9 (medium) |
| T1112 | 7979dd41 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | 7c8c7bd8 | DETECTED | DETECTED | 0 |  | 1 | 0e0255bf-2548-47b8-9582-c0955c9283f5 (high) |
| T1112 | 7f037590 | DETECTED | DETECTED | 0 |  | 1 | 5a93eb65-dffa-4543-b761-94aa60098fb6 (medium); ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | 8023db1e | DETECTED | MISSED | 0 |  | 0 | 5a93eb65-dffa-4543-b761-94aa60098fb6 (medium) |
| T1112 | 81483501 | DETECTED | MISSED | 0 |  | 1 | a1e11042-a74a-46e6-b07c-c4ce8ecc239b (medium) |
| T1112 | 8318ad20 | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | 86677d0e | DETECTED | MISSED | 0 |  | 1 | 37b437cf-3fc5-4c8e-9c94-1d7c9aff842b (medium) |
| T1112 | 8d85a5d8 | DETECTED | MISSED | 0 |  | 1 | 5a93eb65-dffa-4543-b761-94aa60098fb6 (medium) |
| T1112 | 93386d41 | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | a450e469 | DETECTED | DETECTED | 0 |  | 0 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | a4637291 | DETECTED | DETECTED | 0 |  | 1 | 5a93eb65-dffa-4543-b761-94aa60098fb6 (medium); ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | af254e70 | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | b5169fd5 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | bacb3e73 | DETECTED | DETECTED | 0 |  | 1 | 0e0255bf-2548-47b8-9582-c0955c9283f5 (high) |
| T1112 | c0413fb5 | DETECTED | MISSED | 0 |  | 2 | b7e2a8d4-74bb-4b78-adc9-3f92af2d4829 (high); d6a9b252-c666-4de6-8806-5561bbbd3bdc (high) |
| T1112 | c0d6d67f | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | c691cee2 | DETECTED | MISSED | 0 |  | 2 | 0d5675be-bc88-4172-86d3-1e96a4476536 (high); 3f6b7b62-61aa-45db-96bd-9c31b36b653c (high); f674e36a-4b91-431e-8aef-f8a96c2aca35 (medium) |
| T1112 | c8480c83 | DETECTED | DETECTED | 0 |  | 1 | 0e0255bf-2548-47b8-9582-c0955c9283f5 (high) |
| T1112 | d1de3767 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | d29b7faf | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | d49ff3cc | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | d4a6da40 | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1112 | e3ad8e83 | DETECTED | MISSED | 0 |  | 2 | 0d5675be-bc88-4172-86d3-1e96a4476536 (high); 3f6b7b62-61aa-45db-96bd-9c31b36b653c (high) |
| T1112 | e672a340 | MISSED | MISSED | 0 |  | 1 | - |
| T1112 | e8c7c404 | MISSED | MISSED | 0 |  | 0 | - |
| T1112 | ecbd533e | DETECTED | DETECTED | 0 |  | 1 | b0524451-19af-4efa-a46f-562a977f792e (high) |
| T1112 | f2915249 | DETECTED | DETECTED | 0 |  | 2 | 8fbe98a8-8f9d-44f8-aa71-8c572e29ef06 (high) |
| T1112 | fe7974e5 | DETECTED | MISSED | 0 |  | 3 | 28ac00d6-22d9-4a3c-927f-bbd770104573 (high); d6ce7ebd-260b-4323-9768-a9631c8d4db2 (high) |
| T1112 | ffbb407e | DETECTED | DETECTED | 0 |  | 1 | ccc946a3-f65a-432a-bb6f-efc6acc1fd27 (medium); e2482f8d-3443-4237-b906-cc145d87a076 (medium) |
| T1113 | 5a496325 | DETECTED | DETECTED | 0 |  | 1 | 536e2947-3729-478c-9903-745aaffe60d2 (medium); 5dfc1465-8f65-4fde-8eb5-6194380c6a62 (medium); 75180c5f-4ea1-461a-a4f6-6e4700c065d4 (medium); 817f252c-5143-4dae-b418-48c3e9f63728 (medium) |
| T1136.001 | 6657864e | DETECTED | MISSED | 0 |  | 1 | cd219ff3-fa99-45d4-8380-a7d15116c6dc (medium) |
| T1136.001 | bc8be0ac | DETECTED | MISSED | 0 |  | 1 | 243de76f-4725-4f2e-8225-a8a69b15ad61 (medium); 4fdc44df-bfe9-4fcc-b041-68f5a2d3031c (medium) |
| T1136.001 | fda74566 | DETECTED | DETECTED | 0 |  | 1 | ad720b90-25ad-43ff-9b5e-5c841facc8e5 (medium); cd219ff3-fa99-45d4-8380-a7d15116c6dc (medium) |
| T1205.002 | 0284704c | MISSED | MISSED | 0 |  | 0 | - |
| T1205.002 | e69a8f7f | MISSED | MISSED | 0 |  | 0 | - |
| T1217 | 74094120 | MISSED | MISSED | 0 |  | 0 | - |
| T1222 | 6c4ac96f | DETECTED | DETECTED | 0 |  | 1 | c0b2768a-dd06-4671-8339-b16ca8d1f27f (medium) |
| T1222 | 6cd715aa | MISSED | MISSED | 0 |  | 0 | - |
| T1222 | 78bef0d4 | MISSED | MISSED | 0 |  | 1 | - |
| T1518.001 | 015cd268 | MISSED | MISSED | 0 |  | 1 | - |
| T1518.001 | 9dca5a1d | MISSED | MISSED | 0 |  | 0 | - |
| T1518.001 | d3415a0e | MISSED | MISSED | 1 |  | 0 | - |
| T1518.001 | fe613cf3 | DETECTED | MISSED | 0 |  | 1 | 37db85d1-b089-490a-a59a-c7b6f984f480 (high) |
| T1546 | 17d1a3cc | DETECTED | DETECTED | 0 |  | 1 | 833ef470-fa01-4631-a79b-6f291c9ac498 (high) |
| T1546.001 | 10a08978 | MISSED | MISSED | 0 |  | 1 | - |
| T1546.003 | 3c64f177 | DETECTED | MISSED | 0 |  | 0 | 9e07f6e7-83aa-45c6-998e-0af26efd0a85 (medium) |
| T1546.003 | 67cee1c5 | DETECTED | MISSED | 0 |  | 0 | fb843269-508c-4b76-8b8d-88679db22ce7 (medium) |
| T1546.003 | fecd0dfd | DETECTED | DETECTED | 0 |  | 0 | 2c28c248-7f50-417a-9186-a85b223010ee (medium) |
| T1546.008 | 1db380da | DETECTED | DETECTED | 0 |  | 2 | fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1546.008 | 2002f5ea | DETECTED | DETECTED | 0 |  | 2 | fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1546.008 | 210be7ea | DETECTED | DETECTED | 0 |  | 2 | fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1546.008 | 3309f53e | DETECTED | DETECTED | 0 |  | 1 | ae215552-081e-44c7-805f-be16f975c8a2 (high) |
| T1546.008 | 444ff124 | DETECTED | DETECTED | 1 |  | 2 | 9577edbb-851f-4243-8c91-1d5b50c1a39b (medium); f24bcaea-0cd1-11eb-adc1-0242ac120002 (medium) |
| T1546.008 | 5e4fa70d | DETECTED | DETECTED | 0 |  | 2 | fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1546.008 | 7125eba8 | DETECTED | DETECTED | 0 |  | 3 | 9577edbb-851f-4243-8c91-1d5b50c1a39b (medium) |
| T1546.008 | 825ba8ca | DETECTED | DETECTED | 0 |  | 2 | fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1546.008 | 934e90cf | DETECTED | DETECTED | 0 |  | 0 | 1070db9a-3e5d-412e-8e7b-7183b616e1b3 (critical); fff9d2b7-e11c-4a69-93d3-40ef66189767 (medium) |
| T1546.011 | 9b6a06f9 | MISSED | MISSED | 0 |  | 0 | - |
| T1546.012 | 13117939 | MISSED | MISSED | 0 |  | 4 | - |
| T1546.012 | 46b1f278 | DETECTED | DETECTED | 0 |  | 1 | 36803969-5421-41ec-b92f-8500f79c23b0 (high); cbf93e5d-ca6c-4722-8bea-e9119007c248 (medium) |
| T1546.012 | fdda2626 | DETECTED | MISSED | 0 |  | 1 | cbf93e5d-ca6c-4722-8bea-e9119007c248 (medium) |
| T1547.001 | 1d958c61 | DETECTED | MISSED | 0 |  | 2 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium); cbf93e5d-ca6c-4722-8bea-e9119007c248 (medium) |
| T1547.001 | 554cbd88 | DETECTED | DETECTED | 0 |  | 1 | 20f0ee37-5942-4e45-b7d5-c5b5db9df5cd (medium); 24357373-078f-44ed-9ac4-6d334a668a11 (medium); de587dce-915e-4218-aac4-835ca6af6f70 (medium) |
| T1547.001 | 6e1666d5 | DETECTED | DETECTED | 0 |  | 1 | 38879043-7e1e-47a9-8d46-6bec88e201df (medium); f674e36a-4b91-431e-8aef-f8a96c2aca35 (medium) |
| T1547.001 | a70faea1 | DETECTED | MISSED | 0 |  | 0 | 20f0ee37-5942-4e45-b7d5-c5b5db9df5cd (medium) |
| T1547.001 | acfef903 | DETECTED | DETECTED | 0 |  | 1 | 855bc8b5-2ae8-402e-a9ed-b889e6df1900 (medium); 8f3ab69a-aa22-4943-aa58-e0a52fdf6818 (high); f5d19838-41b5-476c-98d8-ba8af4929ee2 (high) |
| T1547.001 | b051b3c0 | DETECTED | MISSED | 0 |  | 2 | f674e36a-4b91-431e-8aef-f8a96c2aca35 (medium) |
| T1547.001 | b5c9a9bc | DETECTED | MISSED | 0 |  | 0 | 20f0ee37-5942-4e45-b7d5-c5b5db9df5cd (medium) |
| T1547.001 | de47f4a0 | MISSED | MISSED | 0 |  | 1 | - |
| T1547.001 | f7fab6cc | DETECTED | MISSED | 0 |  | 2 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium); cbf93e5d-ca6c-4722-8bea-e9119007c248 (medium) |
| T1547.005 | afdfd7e3 | MISSED | MISSED | 0 | yes | 2 | - |
| T1547.005 | de3f8e74 | MISSED | MISSED | 0 |  | 0 | - |
| T1547.006 | e5cb5564 | MISSED | MISSED | 0 |  | 0 | - |
| T1547.014 | 04d55cef | MISSED | MISSED | 0 |  | 0 | - |
| T1547.014 | 39e417dd | MISSED | MISSED | 0 |  | 0 | - |
| T1547.014 | deff4586 | MISSED | MISSED | 0 |  | 0 | - |
| T1552.001 | 0d4f2281 | MISSED | MISSED | 0 |  | 0 | - |
| T1552.001 | b0cdacf6 | MISSED | MISSED | 1 |  | 1 | - |
| T1559 | 7a8f8ae9 | DETECTED | DETECTED | 0 |  | 0 | ba3f5c1b-6272-4119-9dbd-0bc8d21c2702 (high); dcaa3f04-70c3-427a-80b4-b870d73c94c4 (medium) |
| T1564 | 2ec63cc2 | DETECTED | MISSED | 0 |  | 1 | cd219ff3-fa99-45d4-8380-a7d15116c6dc (medium) |
| T1564 | 5bb20389 | DETECTED | MISSED | 0 |  | 1 | 243de76f-4725-4f2e-8225-a8a69b15ad61 (medium); 4fdc44df-bfe9-4fcc-b041-68f5a2d3031c (medium) |
| T1564.001 | 7f66d539 | MISSED | MISSED | 0 |  | 2 | - |
| T1564.001 | d380c318 | MISSED | MISSED | 0 |  | 1 | - |
| T1564.001 | dadb792e | DETECTED | DETECTED | 0 |  | 1 | 4281cb20-2994-4580-aa63-c8b86d019934 (medium) |
| T1564.001 | f650456b | DETECTED | MISSED | 0 |  | 1 | 5a5152f1-463f-436b-b2f5-8eceb3964b42 (medium) |
| T1564.001 | f70974c8 | DETECTED | DETECTED | 0 |  | 1 | efec536f-72e8-4656-8960-5e85d091345b (high) |
| T1564.002 | 173126b7 | DETECTED | DETECTED | 0 |  | 2 | 9ec9fb1b-e059-4489-9642-f270c207923d (medium); b7e2a8d4-74bb-4b78-adc9-3f92af2d4829 (high); b9f0e6f5-09b4-4358-bae4-08408705bd5c (high); cd219ff3-fa99-45d4-8380-a7d15116c6dc (medium); f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd (high) |
| T1592.001 | d430bf85 | MISSED | MISSED | 0 |  | 0 | - |
| T1614.001 | 69f625ba | MISSED | MISSED | 0 |  | 1 | - |
| T1622 | 58bd8c8d | MISSED | MISSED | 0 |  | 0 | - |
| T1653 | 84933ae7 | DETECTED | DETECTED | 0 |  | 0 | f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b (medium) |
| T1653 | ac77e6c0 | MISSED | MISSED | 0 |  | 0 | - |
| T1653 | d4acd6ff | MISSED | MISSED | 0 |  | 2 | - |
| T1653 | eb271877 | MISSED | MISSED | 0 |  | 0 | - |
| T1685 | 5e27f36d | DETECTED | MISSED | 0 |  | 0 | 851c506b-6b7c-4ce2-8802-c703009d03c0 (medium) |
| T1685 | 9719d0e1 | DETECTED | MISSED | 0 |  | 5 | b7e2a8d4-74bb-4b78-adc9-3f92af2d4829 (high) |
| T1685 | d6d22332 | DETECTED | MISSED | 0 |  | 2 | b7e2a8d4-74bb-4b78-adc9-3f92af2d4829 (high) |
| T1685 | d8c57eaa | MISSED | MISSED | 0 |  | 0 | - |
