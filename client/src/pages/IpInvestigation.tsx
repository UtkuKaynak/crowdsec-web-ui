import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { IpInvestigationPanel } from '../components/IpInvestigationPanel';
import { useI18n } from '../lib/i18n';

export function IpInvestigation() {
    const { ip = '' } = useParams();
    const navigate = useNavigate();
    const { t } = useI18n();

    return (
        <div className="space-y-4">
            <button
                type="button"
                onClick={() => navigate(-1)}
                className="inline-flex items-center gap-1 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 transition-colors cursor-pointer"
            >
                <ArrowLeft size={16} />
                {t('common.back')}
            </button>
            {ip ? (
                <IpInvestigationPanel key={ip} ip={ip} />
            ) : (
                <div className="text-sm text-gray-500 dark:text-gray-400">{t('pages.ipInvestigation.noIp')}</div>
            )}
        </div>
    );
}

export default IpInvestigation;
