from manager import PluginManager


def main():

    manager = PluginManager(
        max_workers=4
    )

    case = manager.create_case(
        "CASE-TEST-001"
    )

    evidence = [
        {
            "path": r"C:\evidence\disk01.E01",
            "type": "disk"
        },

        {
            "path": r"C:\evidence\disk02.raw",
            "type": "disk"
        },

        {
            "path": r"C:\evidence\memory.raw",
            "type": "memory"
        },

        {
            "path": r"C:\evidence\attack.pcap",
            "type": "pcap"
        },

        {
            "path": r"C:\evidence\capture2.pcapng",
            "type": "pcap"
        },

        {
            "path": r"C:\evidence\$MFT",
            "type": "mft"
        },

        {
            "path": r"C:\evidence\CMD.EXE-12345678.pf",
            "type": "prefetch"
        },

        {
            "path": r"C:\evidence\$I12345.txt",
            "type": "recyclebin"
        },

        {
            "path": r"C:\evidence\7e4d4b0688000000.automaticDestinations-ms",
            "type": "jumplist"
        }
    ]

    manager.register_evidence(
        case,
        evidence
    )

    print("\nRegistered Evidence:")

    for item in case.evidence:

        print(
            f"{item.evidence_id} | "
            f"{item.name} | "
            f"{item.evidence_type}"
        )

    manager.execute_case(case)


if __name__ == "__main__":
    main()