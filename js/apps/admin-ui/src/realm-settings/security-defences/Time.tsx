import { CSSProperties } from "react";
import { useTranslation } from "react-i18next";

import { TimeSelectorControl } from "../../components/time-selector/TimeSelectorControl";

export const Time = ({
  name,
  labelName = name,
  defaultValue = "",
  style,
  min,
}: {
  name: string;
  labelName?: string;
  defaultValue?: number | "";
  style?: CSSProperties;
  min?: number;
}) => {
  const { t } = useTranslation();
  return (
    <TimeSelectorControl
      name={name}
      style={style}
      label={t(labelName)}
      labelIcon={t(`${labelName}Help`)}
      min={min}
      controller={{
        defaultValue,
        rules: { required: t("required"), min: min },
      }}
    />
  );
};
