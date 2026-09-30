using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using CleanSweep.App.Helpers;
using CleanSweep.Core.Modules;

namespace CleanSweep.App.Controls;

/// <summary>Squarified TreeMap：显示一个目录节点的子目录与直属文件占比。单击子目录触发 NodeClicked。</summary>
public sealed class TreeMapControl : Canvas
{
    public static readonly DependencyProperty NodeProperty = DependencyProperty.Register(
        nameof(Node), typeof(DirectoryNode), typeof(TreeMapControl),
        new FrameworkPropertyMetadata(null, (d, _) => ((TreeMapControl)d).Rebuild()));

    public DirectoryNode? Node
    {
        get => (DirectoryNode?)GetValue(NodeProperty);
        set => SetValue(NodeProperty, value);
    }

    public event EventHandler<DirectoryNode>? NodeClicked;

    private static readonly Color[] Palette =
    {
        Color.FromRgb(0x4F, 0x8F, 0xD6), Color.FromRgb(0x5B, 0xB3, 0x8A), Color.FromRgb(0xE0, 0xA4, 0x4A),
        Color.FromRgb(0xC9, 0x6B, 0x6B), Color.FromRgb(0x8E, 0x7C, 0xC3), Color.FromRgb(0x4E, 0xB4, 0xC4),
        Color.FromRgb(0xA5, 0xA5, 0x5A), Color.FromRgb(0xD3, 0x7F, 0xB0),
    };

    public TreeMapControl()
    {
        Background = new SolidColorBrush(Color.FromRgb(0xF0, 0xF0, 0xF0));
        ClipToBounds = true;
        SizeChanged += (_, _) => Rebuild();
    }

    private sealed record Cell(string Label, long Size, DirectoryNode? Dir, int ColorIndex);

    private void Rebuild()
    {
        Children.Clear();
        var node = Node;
        if (node is null || ActualWidth < 4 || ActualHeight < 4 || node.SizeBytes <= 0) return;

        var cells = new List<Cell>();
        int ci = 0;
        foreach (var c in node.Children.Where(c => c.SizeBytes > 0))
            cells.Add(new Cell(c.Name, c.SizeBytes, c, ci++ % Palette.Length));
        if (node.OwnFilesBytes > 0)
            cells.Add(new Cell("[文件]", node.OwnFilesBytes, null, -1));

        cells.Sort((a, b) => b.Size.CompareTo(a.Size));

        // 过小的块合并成"其他"
        double totalArea = ActualWidth * ActualHeight;
        long total = cells.Sum(c => c.Size);
        if (total <= 0) return;

        var visible = new List<Cell>();
        long otherSize = 0;
        foreach (var c in cells)
        {
            var area = totalArea * c.Size / total;
            if (area >= 60 && visible.Count < 120) visible.Add(c);
            else otherSize += c.Size;
        }
        if (otherSize > 0) visible.Add(new Cell("[其他]", otherSize, null, -2));

        Squarify(visible, new Rect(0, 0, ActualWidth, ActualHeight), total);
    }

    private void Squarify(List<Cell> items, Rect rect, long total)
    {
        if (items.Count == 0 || rect.Width <= 0 || rect.Height <= 0) return;

        double scale = rect.Width * rect.Height / total;
        var areas = items.Select(c => c.Size * scale).ToList();

        int index = 0;
        var remaining = rect;

        while (index < items.Count)
        {
            bool horizontal = remaining.Width >= remaining.Height;
            double side = horizontal ? remaining.Height : remaining.Width;
            if (side <= 0.5) break;

            int start = index;
            double sum = 0;
            double best = double.MaxValue;

            while (index < items.Count)
            {
                double newSum = sum + areas[index];
                double worst = WorstRatio(areas, start, index, newSum, side);
                if (index > start && worst > best) break;
                sum = newSum;
                best = worst;
                index++;
            }

            double thickness = sum / side;
            double offset = 0;
            for (int i = start; i < index; i++)
            {
                double len = thickness <= 0 ? 0 : areas[i] / thickness;
                Rect r = horizontal
                    ? new Rect(remaining.X, remaining.Y + offset, thickness, len)
                    : new Rect(remaining.X + offset, remaining.Y, len, thickness);
                AddCell(items[i], r, total);
                offset += len;
            }

            remaining = horizontal
                ? new Rect(remaining.X + thickness, remaining.Y, Math.Max(0, remaining.Width - thickness), remaining.Height)
                : new Rect(remaining.X, remaining.Y + thickness, remaining.Width, Math.Max(0, remaining.Height - thickness));
        }
    }

    private static double WorstRatio(List<double> areas, int start, int endInclusive, double sum, double side)
    {
        double s2 = sum * sum;
        double w2 = side * side;
        double worst = 0;
        for (int i = start; i <= endInclusive; i++)
        {
            var a = areas[i];
            if (a <= 0) continue;
            worst = Math.Max(worst, Math.Max(w2 * a / s2, s2 / (w2 * a)));
        }
        return worst;
    }

    private void AddCell(Cell c, Rect r, long total)
    {
        if (r.Width < 1 || r.Height < 1) return;

        var baseColor = c.ColorIndex switch
        {
            -1 => Color.FromRgb(0xB0, 0xB0, 0xB0),
            -2 => Color.FromRgb(0xD0, 0xD0, 0xD0),
            _ => Palette[c.ColorIndex],
        };

        var shape = new Rectangle
        {
            Width = Math.Max(0, r.Width - 1),
            Height = Math.Max(0, r.Height - 1),
            Fill = new SolidColorBrush(baseColor),
            Stroke = Brushes.White,
            StrokeThickness = 1,
            RadiusX = 2,
            RadiusY = 2,
            Cursor = c.Dir is not null ? Cursors.Hand : Cursors.Arrow,
            ToolTip = $"{c.Label}\n{Format.Bytes(c.Size)} · {Format.Percent(c.Size, total)}" +
                      (c.Dir is not null ? $"\n{c.Dir.FileCount:N0} 个文件" : ""),
        };
        SetLeft(shape, r.X);
        SetTop(shape, r.Y);

        if (c.Dir is not null)
        {
            var dir = c.Dir;
            shape.MouseLeftButtonUp += (_, _) => NodeClicked?.Invoke(this, dir);
            shape.MouseEnter += (_, _) => shape.Opacity = 0.8;
            shape.MouseLeave += (_, _) => shape.Opacity = 1.0;
        }
        Children.Add(shape);

        if (r.Width >= 48 && r.Height >= 30)
        {
            var label = new TextBlock
            {
                Text = $"{c.Label}\n{Format.Bytes(c.Size)}",
                Foreground = Brushes.White,
                FontSize = 11,
                Margin = new Thickness(6, 4, 0, 0),
                Width = r.Width - 8,
                Height = r.Height - 6,
                TextTrimming = TextTrimming.CharacterEllipsis,
                IsHitTestVisible = false,
            };
            SetLeft(label, r.X);
            SetTop(label, r.Y);
            Children.Add(label);
        }
    }
}
