# sigma/metrology/plotter.py
import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
from matplotlib.ticker import ScalarFormatter, FormatStrFormatter
from matplotlib.patches import ConnectionPatch
from scipy.stats import norm


class SigmaAcademicPlotter:
    """
    Tier-1 Conference Graph Generator for the Sigma Framework.
    Implements Anti-Occlusion visual rendering (Alpha blending, varied markers,
    and distinct linestyles) to handle mathematically identical superimposed curves.
    """

    def __init__(self, output_dir: str = "plots"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        plt.rcParams.update(
            {
                "font.family": "serif",
                "font.serif": ["Times New Roman", "DejaVu Serif", "serif"],
                "font.size": 10,
                "axes.titlesize": 12,
                "axes.labelsize": 11,
                "axes.titlepad": 12,
                "xtick.labelsize": 9,
                "ytick.labelsize": 9,
                "legend.fontsize": 9,
                "legend.frameon": False,
                "figure.dpi": 300,
                "axes.grid": True,
                "grid.alpha": 0.35,
                "grid.linestyle": "--",
                "grid.color": "#b0b0b0",
                "axes.facecolor": "white",
                "savefig.bbox": "tight",
                "axes.spines.top": False,
                "axes.spines.right": False,
            }
        )

        self.colors = {
            "paranoid": "#D55E00",
            "simultaneous": "#0072B2",
            "lightweight": "#009E73",
            "realtime": "#CC79A7",
            "baseline": "#7F7F7F",
            "ideal": "#000000",
        }

        # Anti-Occlusion Styles
        self.styles = {
            "paranoid": {"marker": "o", "ls": "-"},
            "simultaneous": {"marker": "s", "ls": "--"},
            "lightweight": {"marker": "^", "ls": "-."},
            "realtime": {"marker": "D", "ls": ":"},
        }

    def _load(self, filename: str) -> dict:
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARNING] Could not load {filename}: {e}")
            return {}

    def _save_plot(self, fig, filename: str):
        pdf_path = os.path.join(self.output_dir, f"{filename}.pdf")
        png_path = os.path.join(self.output_dir, f"{filename}.png")
        fig.savefig(pdf_path, format="pdf", dpi=300)
        fig.savefig(png_path, format="png", dpi=300)
        plt.close(fig)
        print(f"  -> Generated: {pdf_path}")

    def _create_global_legend(
        self, include_ideal=False, ideal_label="Shannon Saturation"
    ):
        """Forces Matplotlib to render a complete legend regardless of data occlusion."""
        handles = []
        for strat in ["paranoid", "simultaneous", "lightweight", "realtime"]:
            handles.append(
                mlines.Line2D(
                    [],
                    [],
                    color=self.colors[strat],
                    marker=self.styles[strat]["marker"],
                    linestyle=self.styles[strat]["ls"],
                    markersize=5,
                    label=strat.capitalize(),
                )
            )
        if include_ideal:
            handles.append(
                mlines.Line2D(
                    [],
                    [],
                    color=self.colors["ideal"],
                    linestyle=":",
                    lw=1.2,
                    label=ideal_label,
                )
            )
        return handles

    # ==========================================
    # FIG 1: DIFFUSION PROFILING (FACET GRID PER STRATEGY + LOG SCALE)
    # ==========================================
    def plot_diffusion_velocity(self):
        data = self._load("sigma_diffusion_metrics.json")
        if not data:
            return

        # Generate ONE independent image per Strategy
        for strat, payloads in data.items():

            sorted_payloads = sorted(
                list(payloads.keys()),
                key=lambda x: int(x.split("_")[1].replace("B", "")),
            )
            num_plots = len(sorted_payloads)
            if num_plots == 0:
                continue

            # 3-column grid to let the 5 payloads breathe (2x3 Grid)
            cols = 3
            rows = (num_plots + cols - 1) // cols

            fig, axes = plt.subplots(
                rows, cols, figsize=(12, 3.5 * rows), sharey=True, sharex=True
            )
            plt.subplots_adjust(wspace=0.08, hspace=0.3)

            if num_plots == 1:
                axes = [axes]
            else:
                axes = axes.flatten()

            for idx, p_key in enumerate(sorted_payloads):
                ax = axes[idx]
                rd = payloads[p_key]["round_data"]
                t_bits = payloads[p_key]["target_bits"]

                # Complete dataset without clipping
                rounds = sorted([int(k.split("_")[1]) for k in rd.keys()])
                diff = np.array(
                    [rd[f"round_{r}"]["diffusion_percentage"] for r in rounds]
                )
                stdev = np.array(
                    [rd[f"round_{r}"]["stdev_hamming_distance"] for r in rounds]
                )
                stdev_pct = (stdev / t_bits) * 100.0

                # Use the current strategy's color
                color = self.colors.get(strat, "black")
                marker = self.styles.get(strat, {}).get("marker", "o")

                # Plot the curve and its standard deviation shadow
                ax.plot(
                    rounds,
                    diff,
                    marker=marker,
                    markersize=4,
                    lw=1.5,
                    color=color,
                    alpha=0.85,
                )
                ax.fill_between(
                    rounds,
                    diff - stdev_pct,
                    diff + stdev_pct,
                    color=color,
                    alpha=0.15,
                    linewidth=0,
                )

                # Shannon limit baseline
                ax.axhline(y=50.0, color=self.colors["ideal"], ls="--", lw=1.2)

                # Subplot formatting
                p_size = p_key.split("_")[1]
                ax.set_title(
                    f"Payload: {p_size}", fontsize=11, fontweight="bold", pad=10
                )
                ax.set_ylim(0, 100)

                # LOGARITHMIC SCALE: Solves the wall effect without hiding rounds
                ax.set_xscale("log", base=2)
                ax.xaxis.set_major_formatter(ScalarFormatter())

                # Clean axis labels (only on the edges)
                if idx % cols == 0:
                    ax.set_ylabel("Bitwise Diffusion (%)", fontsize=10)
                if idx >= (rows - 1) * cols or (idx + cols) >= len(axes):
                    ax.set_xlabel("Computational Rounds (Log$_2$)", fontsize=10)

            # Turn off empty axes if any (e.g., the 6th plot in a 2x3 grid)
            for idx in range(num_plots, len(axes)):
                axes[idx].axis("off")

            # Insert legend in the empty box
            if num_plots < len(axes):
                empty_ax = axes[num_plots]
                empty_ax.plot(
                    [],
                    [],
                    color=self.colors["ideal"],
                    ls="--",
                    lw=1.2,
                    label="Shannon Saturation (50%)",
                )
                empty_ax.legend(loc="center", fontsize=11, frameon=False)

            fig.suptitle(
                f"ARX Avalanche Velocity - Topology: {strat.capitalize()}",
                fontsize=15,
                y=0.98,
            )

            # Save a dedicated file per strategy
            self._save_plot(fig, f"fig_1_diffusion_{strat}")

    # ==========================================
    # FIG 2: THROUGHPUT SCALING
    # ==========================================
    def plot_throughput_scaling(self):
        data = self._load("sigma_metrics.json")
        if not data or "throughput_scaling" not in data.get("experiments", {}):
            return
        fig, ax = plt.subplots(figsize=(7, 4.5))

        scaling_data = data["experiments"]["throughput_scaling"]
        sizes = sorted([float(s) for s in scaling_data.keys()])

        strats = set()
        for s in scaling_data.values():
            strats.update(s.keys())

        for strat in sorted(list(strats)):
            thr = [
                scaling_data[str(s)].get(strat, {}).get("throughput_mb_s", 0)
                for s in sizes
            ]
            color = self.colors.get(strat, "black")
            marker = self.styles.get(strat, {}).get("marker", "o")
            ls = self.styles.get(strat, {}).get("ls", "-")
            ax.plot(
                sizes,
                thr,
                marker=marker,
                markersize=4,
                lw=1.5,
                ls=ls,
                color=color,
                alpha=0.85,
            )

        ax.set_title("Asymptotic Throughput Scaling via PCIe/NVMe")
        ax.set_xlabel("Payload Size (MB)")
        ax.set_ylabel("Throughput (MB/s)")
        ax.set_xscale("log", base=10)
        ax.xaxis.set_major_formatter(ScalarFormatter())

        # Explicit Forced Legend
        ax.legend(handles=self._create_global_legend(), loc="upper left")
        self._save_plot(fig, "fig_2_throughput_scaling")

    # ==========================================
    # FIG 3: POW LINEARITY
    # ==========================================
    def plot_pow_linearity(self):
        data = self._load("sigma_metrics.json")
        if not data or "pow_linearity" not in data.get("experiments", {}):
            return
        fig, ax = plt.subplots(figsize=(7, 4.5))

        pow_data = data["experiments"]["pow_linearity"]
        rounds = sorted([int(k) for k in pow_data.keys()])
        times = [pow_data[str(r)] for r in rounds]

        ax.plot(
            rounds,
            times,
            marker="d",
            markersize=4,
            color=self.colors["paranoid"],
            lw=1.5,
        )
        ax.set_title("Proof-of-Work Asymptotic Linearity $\mathcal{O}(R)$")
        ax.set_xlabel("Computational Rounds ($R$)")
        ax.set_ylabel("Execution Latency (Seconds)")
        self._save_plot(fig, "fig_3_pow_linearity")

    # ==========================================
    # FIG 4: STOCHASTIC ENTROPY (Lollipop Chart)
    # ==========================================
    def plot_stochastic_entropy(self):
        data = self._load("sigma_stochastic_metrics.json")
        if not data:
            return
        fig, ax = plt.subplots(figsize=(7, 4.5))

        strategies = sorted(list(data.keys()))
        entropies = [data[s]["stream_shannon_entropy"] for s in strategies]
        colors = [self.colors.get(s, "black") for s in strategies]
        x_positions = np.arange(len(strategies))

        # Y-axis base tightly adjusted to reveal microscopic noise
        base_y = 7.99985

        # Draw the "lollipops" (vertical line + dot)
        ax.vlines(
            x=x_positions,
            ymin=base_y,
            ymax=entropies,
            color=colors,
            alpha=0.7,
            linewidth=2,
        )
        ax.scatter(
            x_positions, entropies, color=colors, s=100, zorder=3, edgecolor="black"
        )

        # Ideal line (White Noise)
        ax.axhline(
            y=8.0,
            color=self.colors["ideal"],
            ls="--",
            lw=1.5,
            zorder=1,
            label="Ideal Uniform Dist. (8.0 bits)",
        )

        ax.set_ylim(base_y, 8.00002)
        ax.set_xticks(x_positions)
        ax.set_xticklabels([s.capitalize() for s in strategies])
        ax.set_ylabel("Stream Shannon Entropy (bits/byte)")
        ax.set_title("Stochastic PRNG Quality (Micro-Variance Analysis)")
        ax.yaxis.set_major_formatter(FormatStrFormatter("%.5f"))

        # Exact annotations
        for x, y in zip(x_positions, entropies):
            ax.text(
                x,
                y + 0.00001,
                f"{y:.6f}",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="bold",
            )

        ax.legend(loc="upper left", frameon=False)
        self._save_plot(fig, "fig_4_stochastic_entropy")

    # ==========================================
    # FIG 5: DFA RESILIENCE (Compact Bar Chart)
    # ==========================================
    def plot_dfa_resilience(self):
        data = self._load("sigma_dfa_metrics.json")
        if not data:
            return

        # 1. Drastically reduce canvas size to 4.0 x 3.5 inches
        fig, ax = plt.subplots(figsize=(4.0, 3.5))

        fault_hd = data.get(
            "mean_hamming_distance_of_fault",
            data.get("mean_fault_hamming_distance", 128),
        )
        ideal_hd = data.get("ideal_hamming_distance", 128)

        labels = ["Observed Fault\nPropagation", "Ideal Random\nOracle"]
        values = [fault_hd, ideal_hd]
        colors = [self.colors["paranoid"], self.colors["baseline"]]

        bars = ax.bar(
            labels,
            values,
            color=colors,
            alpha=0.85,
            width=0.4,  # Slightly narrower bars to let them breathe
            edgecolor="black",
            linewidth=0.5,
        )

        ax.set_ylim(0, ideal_hd * 1.3)
        ax.set_ylabel("Mean Hamming Distance (Bits)", fontsize=10)
        ax.set_title("Differential Fault Analysis (DFA)", fontsize=11)

        for bar in bars:
            yval = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                yval + 2,
                f"{yval:.2f}",
                ha="center",
                va="bottom",
                fontsize=9,
            )

        # 2. Remove any excess whitespace around the plot
        plt.tight_layout()
        self._save_plot(fig, "fig_5_dfa_resilience")

    # ==========================================
    # FIG 6: TVLA INTERPRETER LEAKAGE (Dual Density)
    # ==========================================
    def plot_tvla_leakage(self):
        sigma = self._load("sigma_tvla_metrics.json")
        baseline = self._load("sigma_tvla_baseline_metrics.json")
        if not sigma or not baseline:
            return

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))

        # Auxiliary function to reconstruct the bell curve from the T-test
        def plot_density(ax, mu_fixed, mu_random, t_stat, n_samples, title):
            # Derive sigma from the Welch's T-test formula
            delta_mu = abs(mu_random - mu_fixed)
            sigma = (delta_mu / abs(t_stat)) * np.sqrt(n_samples / 2)

            # Create the X-axis range adapted to the data
            x_min = min(mu_fixed, mu_random) - 4 * sigma
            x_max = max(mu_fixed, mu_random) + 4 * sigma
            x = np.linspace(x_min, x_max, 1000)

            # Draw and fill the curves
            ax.plot(
                x,
                norm.pdf(x, mu_fixed, sigma),
                color="#d62728",
                lw=1.5,
                label="Fixed Payload",
            )
            ax.fill_between(x, norm.pdf(x, mu_fixed, sigma), color="#d62728", alpha=0.3)
            ax.plot(
                x,
                norm.pdf(x, mu_random, sigma),
                color="#1f77b4",
                lw=1.5,
                label="Random Payload",
            )
            ax.fill_between(
                x, norm.pdf(x, mu_random, sigma), color="#1f77b4", alpha=0.3
            )

            ax.axvline(mu_fixed, color="#d62728", linestyle="--", alpha=0.8)
            ax.axvline(mu_random, color="#1f77b4", linestyle="--", alpha=0.8)

            ax.set_title(title, fontsize=11)
            ax.set_xlabel("Execution Time (ns)")

            # Hide Y-axis numbers for visual cleanliness
            ax.set_yticks([])

            # Statistics box
            stats_text = f"$\\Delta \\mu = {delta_mu:,.1f}$ ns\n$t = {t_stat:.2f}$"
            ax.text(
                0.05,
                0.85,
                stats_text,
                transform=ax.transAxes,
                fontsize=10,
                bbox=dict(
                    facecolor="white",
                    alpha=0.9,
                    edgecolor="#b0b0b0",
                    boxstyle="round,pad=0.5",
                ),
            )

        # Generate Panel A: Sigma Core
        plot_density(
            ax1,
            sigma["mean_ns_fixed"],
            sigma["mean_ns_random"],
            sigma["t_statistic"],
            sigma.get("samples_fixed", 250000),
            "Panel A: Sigma Core ($\\Psi$ Topology)",
        )
        ax1.set_ylabel("Probability Density")
        ax1.legend(loc="upper right", fontsize=9)

        # Generate Panel B: Baseline Null Cipher
        plot_density(
            ax2,
            baseline["mean_ns_fixed"],
            baseline["mean_ns_random"],
            baseline["t_statistic"],
            250000,
            "Panel B: Baseline Control (Null Cipher)",
        )

        fig.suptitle(
            "TVLA: Isolating Interpreter Artifacts via Control Group",
            fontsize=14,
            y=0.98,
        )
        plt.tight_layout()
        self._save_plot(fig, "fig_6_tvla_leakage")

    # ==========================================
    # FIG 7: MICROARCH CROSSOVER
    # ==========================================
    def plot_microarch_crossover(self):
        data = self._load("sigma_microarch_metrics.json")
        if not data or "crossover_phase" not in data:
            return
        fig, ax = plt.subplots(figsize=(7, 4.5))

        crossover = data["crossover_phase"]
        sizes = sorted([int(k) for k in crossover.keys()])

        lw_lat = [crossover[str(s)]["lightweight_s"] * 1e6 for s in sizes]
        rt_lat = [crossover[str(s)]["realtime_s"] * 1e6 for s in sizes]

        ax.plot(
            sizes,
            lw_lat,
            marker=self.styles["lightweight"]["marker"],
            markersize=4,
            lw=1.5,
            ls=self.styles["lightweight"]["ls"],
            color=self.colors["lightweight"],
            alpha=0.85,
            label="Lightweight (Merkle)",
        )
        ax.plot(
            sizes,
            rt_lat,
            marker=self.styles["realtime"]["marker"],
            markersize=4,
            lw=1.5,
            ls=self.styles["realtime"]["ls"],
            color=self.colors["realtime"],
            alpha=0.85,
            label="RealTime (Ring Acc.)",
        )

        ax.set_xscale("log", base=2)
        ax.set_yscale("log", base=10)
        ax.set_xlabel("Payload Size (Bytes)")
        ax.set_ylabel(r"Execution Latency ($\mu$s)")
        ax.set_title("Topological Phase Transition (Micro-Latency Crossover)")
        ax.legend(loc="upper left")

        self._save_plot(fig, "fig_7_microarch_crossover")

    # ==========================================
    # FIG 8: ASIC SYNTHESIS (Donut + Data Table)
    # ==========================================
    def plot_asic_synthesis(self):
        data = self._load("sigma_asic_metrics.json")
        if not data:
            return

        fig, ax = plt.subplots(figsize=(6, 4.5))

        ops = data.get("round_metrics", {}).get("operations_per_round", {})
        labels = list(ops.keys())
        sizes = list(ops.values())

        # Academic colors for logic gates
        op_colors = ["#1f77b4", "#ff7f0e", "#2ca02c"]

        # Create Donut Chart
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            autopct="%1.1f%%",
            startangle=90,
            colors=op_colors,
            wedgeprops=dict(width=0.4, edgecolor="w"),
        )

        # --- CORRECTION HERE ---
        # Change 'white' to 'black' and increase size to 10
        plt.setp(autotexts, size=10, weight="bold", color="black")
        # ------------------------

        # Add white central circle for the Donut appearance
        centre_circle = plt.Circle((0, 0), 0.70, fc="white")
        fig.gca().add_artist(centre_circle)

        # Add text to the center
        ax.text(
            0,
            0,
            f"Total Ops:\n{sum(sizes)}",
            ha="center",
            va="center",
            fontsize=11,
            fontweight="bold",
        )
        ax.set_title("$\\Psi$ Core Operation Distribution (Per Round)", pad=20)

        # Extract metadata for the table
        ge = data.get("round_metrics", {}).get("combinational_area_ge", 0)
        delay = data.get("round_metrics", {}).get("critical_path_delay_ns", 0)
        unrolled_ge = data.get("unrolled_ge", 0)

        # Create aesthetic metadata table below the Donut
        table_data = [
            ["Target Node", "TSMC 45nm"],
            ["Combinational Area", f"{ge:,.0f} GE"],
            ["Fully Unrolled Area", f"{unrolled_ge:,.0f} GE"],
            ["Critical Path Delay", f"{delay} ns"],
        ]

        table = plt.table(
            cellText=table_data,
            loc="bottom",
            cellLoc="center",
            bbox=[0.1, -0.3, 0.8, 0.25],
            edges="horizontal",
        )
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 1.5)

        self._save_plot(fig, "fig_8_asic_synthesis")

    def execute_all(self):
        print("=" * 75)
        print("  SIGMA FRAMEWORK - ANTI-OCCLUSION PLOT GENERATOR")
        print("=" * 75 + "\n")

        self.plot_diffusion_velocity()
        self.plot_throughput_scaling()
        self.plot_pow_linearity()
        self.plot_stochastic_entropy()
        self.plot_dfa_resilience()
        self.plot_tvla_leakage()
        self.plot_microarch_crossover()
        self.plot_asic_synthesis()

        print("\n[SUCCESS] All 8 publication-ready assets generated in 'plots/'.")


if __name__ == "__main__":
    plotter = SigmaAcademicPlotter()
    plotter.execute_all()
