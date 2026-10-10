import argparse
import sys
from pathlib import Path

from plugin_orchestrator import PluginOrchestrator
from collector import ArtifactCollector
from merger import ArtifactMerger


def main(memory_image, output_dir=None):

    memory_image = Path(memory_image)

    print("=" * 70)
    print("SHERLOCKGPT MEMORY ANALYSIS")
    print("=" * 70)

    print(
        f"Input RAM image:\n{memory_image}"
    )
    if output_dir:
        print(f"Output directory:\n{output_dir}")

    # ---------------------------------------------------------
    # 1. Execute Volatility plugins
    # ---------------------------------------------------------

    plugin_runner = PluginOrchestrator(
        memory_image,
        output_dir=output_dir
    )

    execution_results = (
        plugin_runner.run_all()
    )

    # ---------------------------------------------------------
    # 2. Collect raw results
    # ---------------------------------------------------------

    collector = ArtifactCollector(
        output_dir=output_dir
    )

    collected_data = (
        collector.collect()
    )

    # ---------------------------------------------------------
    # 3. Create logical artifact outputs
    # ---------------------------------------------------------

    merger = ArtifactMerger(
        collected_data,
        execution_results,
        output_dir=output_dir
    )

    output_files = merger.save()

    # ---------------------------------------------------------
    # 4. Final report
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("MEMORY ANALYSIS COMPLETED")
    print("=" * 70)

    for output_file in output_files:

        print(
            f"done {output_file}"
        )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Memory Forensic Artifact Extractor"
    )

    parser.add_argument(
        "memory_image",
        help="Path to memory image file"
    )

    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output directory for memory extraction results"
    )

    args = parser.parse_args()

    main(
        args.memory_image,
        output_dir=args.output
    )