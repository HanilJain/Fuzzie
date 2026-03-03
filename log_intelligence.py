import os
import re
from collections import Counter


LOG_ROOT = "Logs"


class CrashIntelligence:
    """
    Aggregates crash intelligence across fuzz_* log directories.
    """

    def __init__(self, root_directory=LOG_ROOT):
        self.root = root_directory

        self.total_crashes = 0
        self.reason_counter = Counter()
        self.frame_type_counter = Counter()
        self.malformed_field_counter = Counter()
        self.frames_to_disruption = []

    # -----------------------------------------------------
    def analyze(self):
        self._scan_logs()
        return self._generate_report()

    # -----------------------------------------------------
    def _scan_logs(self):
        """
        Scan only subdirectories under LOG_ROOT that start with 'fuzz_'.
        """

        if not os.path.exists(self.root):
            return

        for entry in os.listdir(self.root):

            if not entry.startswith("fuzz_"):
                continue

            target_path = os.path.join(self.root, entry)

            if not os.path.isdir(target_path):
                continue

            for root, _, files in os.walk(target_path):

                for file in files:
                    full_path = os.path.join(root, file)

                    if file.startswith("Aliveness_check_"):
                        self._process_aliveness_file(full_path)

                    elif file.startswith("frames_till_disr_"):
                        self._process_frames_file(full_path)

    # -----------------------------------------------------
    def _process_aliveness_file(self, path):
        """
        Extract crash reason, frame type, malformed field.
        """

        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            return

        for line in lines:

            # Match lines that begin with timestamp format HH:MM:SS:
            if re.match(r"\d{2}:\d{2}:\d{2}:", line):

                self.total_crashes += 1

                reason = line.split(":", 1)[1].strip()
                self.reason_counter[reason] += 1

                # Extract frame type
                frame_match = re.search(r"sending (.*?) frames", reason)
                if frame_match:
                    frame_type = frame_match.group(1)
                    self.frame_type_counter[frame_type] += 1

                # Extract malformed field
                malformed_match = re.search(r"malformed (.*)", reason)
                if malformed_match:
                    malformed_field = malformed_match.group(1)
                    self.malformed_field_counter[malformed_field] += 1

    # -----------------------------------------------------
    def _process_frames_file(self, path):
        """
        Count number of frames before disruption.
        """

        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            return

        if lines:
            self.frames_to_disruption.append(len(lines))

    # -----------------------------------------------------
    def _generate_report(self):

        report = []
        report.append("\n==== FUZZING INTELLIGENCE SUMMARY ====\n")

        report.append(f"Total Crash Events: {self.total_crashes}")

        # Frame instability ranking
        if self.frame_type_counter:
            report.append("\nFrame Type Instability Ranking:")
            for frame, count in self.frame_type_counter.most_common():
                report.append(f"- {frame}: {count}")
        else:
            report.append("\nFrame Type Instability Ranking: N/A")

        # Sensitive fields ranking
        if self.malformed_field_counter:
            report.append("\nSensitive Fields Ranking:")
            for field, count in self.malformed_field_counter.most_common():
                report.append(f"- {field}: {count}")
        else:
            report.append("\nSensitive Fields Ranking: N/A")

        # Frames to disruption statistics
        if self.frames_to_disruption:
            avg_frames = sum(self.frames_to_disruption) / len(self.frames_to_disruption)
            report.append(
                f"\nAverage Frames Before Disruption: {round(avg_frames, 2)}"
            )

            crash_density = (
                self.total_crashes / avg_frames if avg_frames > 0 else 0
            )

            report.append(
                f"Crash Density Score: {round(crash_density, 4)} crashes/frame"
            )
        else:
            report.append("\nAverage Frames Before Disruption: N/A")

        # Field diversity index
        if self.total_crashes > 0:
            diversity = len(self.malformed_field_counter) / self.total_crashes
            report.append(f"Field Diversity Index: {round(diversity, 2)}")

        report.append("\n======================================\n")

        return "\n".join(report)
