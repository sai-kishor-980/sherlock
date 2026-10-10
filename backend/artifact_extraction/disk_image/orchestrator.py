import argparse
from pathlib import Path

from collector import Collector
from merger import Merger
from context import ExtractionContext

from core.image_reader.image_factory import ImageFactory
from core.partition_extractor import PartitionExtractor
from core.filesystem import FileSystem
from core.user_discovery import UserDiscovery
from plugin_loader import PluginLoader
from extractors.registry.extractor import RegistryExtractor
from extractors.browser.extractor import BrowserExtractor
from extractors.eventlog.extractor import EventLogExtractor
from extractors.prefetch.extractor import PrefetchExtractor
from extractors.recyclebin.extractor import RecycleBinExtractor
from extractors.lnk.extractor import LnkExtractor
from extractors.jumplist.extractor import JumpListExtractor
from extractors.mft.extractor import MFTExtractor
from path_debug import log_path_boundary
def main():

    parser = argparse.ArgumentParser(
        description="Disk Image Artifact Extractor"
    )

    parser.add_argument(
        "image",
        help="Path to disk image (.img/.dd/.001/.E01)"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output directory"
    )

    args = parser.parse_args()
    log_path_boundary("orchestrator args.image", args.image)

    print("=" * 60)
    print("Disk Image Artifact Extraction")
    print("=" * 60)

    # -------------------------------------
    # Open image
    # -------------------------------------

    reader = ImageFactory.create(args.image)
    reader.open()

    collector = Collector()

    try:

        # -------------------------------------
        # Find partitions
        # -------------------------------------

        partition_extractor = PartitionExtractor(reader)
        partitions = partition_extractor.get_partitions()

        if not partitions:
            print("No usable partitions found.")
            return

        # -------------------------------------
        # Process each Windows partition
        # -------------------------------------

        for partition in partitions:

            try:
                fs = FileSystem(reader, partition)

            except Exception as e:
                print(f"Skipping partition {partition.start}: {e}")
                continue

            # Skip non-Windows partitions
            if not fs.exists("/Windows"):
                continue

            print(f"\nWindows Partition Found (Start Sector: {partition.start})")

            users = UserDiscovery(fs).get_users()

            print(f"Users Found : {users}")

            context = ExtractionContext(
                filesystem=fs,
                partition=partition,
                partition_id=partition.start,
                users=users,
                output_dir=args.output,
                image_name=Path(args.image).name
                )

            loader = PluginLoader()

            extractors = loader.load(context)

            for extractor in extractors:

                try:
                    result = extractor.extract()

                    collector.add(result)

                    print(
                        f"[{result['status']}] "
                        f"{result['artifact']} "
                        f"({result['files']} files)"
                    )

                except Exception as e:

                    failed_result = {
                        "artifact": extractor.__class__.__name__,
                        "status": "FAILED",
                        "files": 0,
                        "message": str(e)
                    }

                    collector.add(failed_result)

                    print(
                        f"[FAILED] "
                        f"{extractor.__class__.__name__}: {e}"
                    )

    finally:
        reader.close()

    # -------------------------------------
    # Run Analyzers
    # -------------------------------------
    print("\n" + "=" * 60)
    print("Running Analyzers")
    print("=" * 60)
    
    from analyzers.registry.analyzer import RegistryAnalyzer
    from analyzers.browser.analyzer import BrowserAnalyzer
    from analyzers.eventlogs.analyzer import EventLogsAnalyzer
    from analyzers.jumplist.analyzer import JumpListAnalyzer
    from analyzers.lnk.analyzer import LNKAnalyzer
    from analyzers.mft.analyzer import MFTAnalyzer
    from analyzers.prefetch.analyzer import PrefetchAnalyzer
    from analyzers.recyclebin.analyzer import RecycleBinAnalyzer
    from analyzers.email.analyzer import EmailAnalyzer
    
    output_path = Path(args.output)
    analyzed_path = output_path / "analyzed"
    
    analyzers = [
        RegistryAnalyzer(output_path / "registry", analyzed_path),
        BrowserAnalyzer(output_path / "browser", analyzed_path),
        EventLogsAnalyzer(output_path / "event_logs", analyzed_path),
        JumpListAnalyzer(output_path / "jump_lists", analyzed_path),
        LNKAnalyzer(output_path / "lnk", analyzed_path),
        MFTAnalyzer(output_path / "mft", analyzed_path),
        PrefetchAnalyzer(output_path / "prefetch", analyzed_path),
        RecycleBinAnalyzer(output_path / "recycle_bin", analyzed_path),
        EmailAnalyzer(output_path / "email", analyzed_path),
    ]
    
    for analyzer in analyzers:
        if not analyzer.extracted_data_dir.exists():
            continue

        try:
            analyzer.analyze()

        except Exception as e:
            print(
            f"[!] Error running "
            f"{analyzer.__class__.__name__}: {e}"
        )

    # -------------------------------------
    # Write summary
    # -------------------------------------

    summary = collector.summary()

    summary_file = Merger.write(
        summary,
        args.output
    )

    print(f"\nSummary written to: {summary_file}")

    print("\nExtraction Complete.")


if __name__ == "__main__":
    main()