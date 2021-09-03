import { NativeModules } from 'react-native';

type IoCryptoFastLoginType = {
  multiply(a: number, b: number): Promise<number>;
};

const { IoCryptoFastLogin } = NativeModules;

export default IoCryptoFastLogin as IoCryptoFastLoginType;
