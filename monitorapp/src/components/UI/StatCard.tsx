type StatColor = "blue" | "green" | "purple" | "orange";

interface StatCardProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  value: React.ReactNode;
  subtitle?: string;
  color?: StatColor;
}

export const StatCard = ({
  icon: Icon,
  title,
  value,
  subtitle,
  color = "blue",
}: StatCardProps) => (
  <div
    className={`bg-white rounded-xl shadow-lg p-6 border-l-4 border-${color}-500 hover:shadow-xl transition-all duration-300`}
  >
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-600 text-sm font-medium">{title}</p>
        <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
        {subtitle && <p className="text-gray-500 text-xs mt-1">{subtitle}</p>}
      </div>
      <Icon className={`w-10 h-10 text-${color}-500 opacity-80`} />
    </div>
  </div>
);
