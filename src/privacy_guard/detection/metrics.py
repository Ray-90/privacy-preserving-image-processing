from privacy_guard.config import CLASS_NAMES

def metrics_summary(metrics):
    keys = ['precision', 'recall', 'mAP50', 'mAP50_95']
    summary = {'overall': dict(zip(keys, map(float, metrics.mean_results()))),
               'per_class': {name: None for name in CLASS_NAMES}}
    for position, class_id in enumerate(metrics.ap_class_index):
        summary['per_class'][CLASS_NAMES[int(class_id)]] = dict(
            zip(keys, map(float, metrics.class_result(position))))
    summary['note'] = 'Null means no per-class result was returned, not zero accuracy.'
    return summary
