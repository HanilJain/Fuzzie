import os
import re
from collections import Counter


LOG_ROOT = "Logs"


class CrashIntelligence:

    def __init__(self, root_directory=LOG_ROOT):
        self.root = root_directory
        self.total_crashes = 0
        self.reason_counter = Counter()
        self.frame_type_counter = Counter()
        self.malformed_field_counter = Counter()
        self.frames_to_disruption = []

    # -------------------------------
    def analyze(self):
        self._scan_logs()
        return self._generate_report()

    # -------------------------------
    def _scan_logs(self):
        if not os.path.exists(self.root):
            return

        for root, dirs, files in os.walk(self.root):

            for file in files:
                full_path = os.path.join(root, file)

                if file.startswith("Aliveness_check_"):
                    self._process_aliveness_file(full_path)

                elif file.startswith("frames_till_disr_"):
                    self._process_frames_file(full_path)

    # -------------------------------
    def _process_aliveness_file(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except:
            return

        for line in lines:

            # Match timestamped crash line
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

    # -------------------------------
    def _process_frames_file(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except:
            return

        if len(lines) > 0:
            self.frames_to_disruption.append(len(lines))

    # -------------------------------
    def _generate_report(self):

        report = []
        report.append("\n==== FUZZING INTELLIGENCE SUMMARY ====\n")

        report.append(f"Total Crash Events: {self.total_crashes}")

        # Frame type ranking
        if self.frame_type_counter:
            report.append("\nFrame Type Instability Ranking:")
            for frame, count in self.frame_type_counter.most_common():
                report.append(f"- {frame}: {count}")
        else:
            report.append("Frame Type Instability Ranking: N/A")

        # Field sensitivity ranking
        if self.malformed_field_counter:
            report.append("\nSensitive Fields Ranking:")
            for field, count in self.malformed_field_counter.most_common():
                report.append(f"- {field}: {count}")
        else:
            report.append("Sensitive Fields Ranking: N/A")

        # Frames to disruption
        if self.frames_to_disruption:
            avg_frames = sum(self.frames_to_disruption) / len(self.frames_to_disruption)
            report.append(f"\nAverage Frames Before Disruption: {round(avg_frames, 2)}")

            crash_density = (
                self.total_crashes / avg_frames
                if avg_frames > 0 else 0
            )

            report.append(f"Crash Density Score: {round(crash_density, 4)} crashes/frame")
        else:
            report.append("\nAverage Frames Before Disruption: N/A")

        # Diversity metric
        if self.total_crashes > 0:
            diversity = len(self.malformed_field_counter) / self.total_crashes
            report.append(f"Field Diversity Index: {round(diversity, 2)}")

        report.append("\n======================================\n")

        return "\n".join(report)