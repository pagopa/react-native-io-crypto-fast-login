import { NativeModules } from 'react-native';

type IoCryptoFastLoginType = {
  run_android_code(): Promise<void>;
};

const { IoCryptoFastLogin } = NativeModules;

export default IoCryptoFastLogin as IoCryptoFastLoginType;
