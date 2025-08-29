import { ChevronDown, ChevronUp } from 'lucide-react';

interface SectionHeaderProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  isExpanded: boolean;
  onToggle: () => void;
}
export const SectionHeader = ({
  icon: Icon,
  title,
  isExpanded,
  onToggle,
}: SectionHeaderProps) => (
  <button
    onClick={onToggle}
    className="w-full flex items-center justify-between bg-gradient-to-r from-gray-50 to-gray-100 rounded-lg p-4 mb-4 hover:from-gray-100 hover:to-gray-200 transition-all duration-200"
  >
    <div className="flex items-center space-x-3">
      <Icon className="w-6 h-6 text-gray-700" />
      <h2 className="text-xl font-bold text-gray-800">{title}</h2>
    </div>
    {isExpanded ? (
      <ChevronUp className="w-5 h-5 text-gray-600" />
    ) : (
      <ChevronDown className="w-5 h-5 text-gray-600" />
    )}
  </button>
);
