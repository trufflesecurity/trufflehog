set terminal png size 800,600
set output "hack/bench/versions.png"

set title "User Time vs. Version"
set xlabel "Version"
set ylabel "Average User Time (s)"

set xtics rotate by -45

plot "hack/bench/plot.txt" using 2:xtic(1) with linespoints linestyle 1 notitle
