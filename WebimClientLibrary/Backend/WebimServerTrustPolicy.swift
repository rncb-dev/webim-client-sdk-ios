import Foundation

/// MARK: Протокол Менеджера кастомной проверки соединения с сервером
public protocol WebimServerTrustPolicyManagerProtocol {
    /// Настройка Менеджера
    func setConfig(secKeys: [SecKey], validHost: [String]?)
}

/// MARK: Менеджер кастомной проверки соединения с сервером
public class WebimServerTrustPolicyManager: WebimServerTrustPolicyManagerProtocol {
    static public let shared = WebimServerTrustPolicyManager()
    private var secKeys = [SecKey]()
    private var validHost: [String]?
    
    /// Настройка Менеджера
    /// - Parameter secKeys: Сертификаты
    /// - Parameter validHost: Валидный хост
    public func setConfig(secKeys: [SecKey],
                          validHost: [String]?) {
        self.secKeys = secKeys
        self.validHost = validHost
    }
    
    /// Получить сертификаты
    /// - Returns: Сертификаты
    func getSecKeys() -> [SecKey] {
        return self.secKeys
    }
    
    /// Получить валидный хост
    /// - Returns: Сертификаты
    func getValidHost() -> [String]? {
        return self.validHost
    }
}

/// MARK: Протокол для кастомной проверки соединения с сервером
protocol WebimServerTrustPolicyProtocol {
    /// Проверка валдиности соединения
    func urlSessionValid(challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void)
}

/// MARK: Проверка соединения с сервером
final class WebimServerTrustPolicy: WebimServerTrustPolicyProtocol {
    /// Проверка валдиности соединения
    /// - Parameters:
    ///   - challenge: Задача аутентификации
    ///   - completionHandler: (Константы, переданные делегатами сеанса или задачи в предоставленный блок продолжения в ответ на запрос проверки подлинности и Использовать указанные учетные данные, которые могут быть нулевыми)
    public func urlSessionValid(challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else { return completionHandler(.useCredential, nil) }
        let hosts = WebimServerTrustPolicyManager.shared.getValidHost()
        /// Если соединение валидно то создаем исключение
        if self.validConnection(trust: serverTrust, host: challenge.protectionSpace.host, validHost: hosts) {
            /// Возвращает непрозрачный файл cookie, содержащий исключения из политик доверия, которые позволят успешно выполнить будущие оценки текущего сертификата
            let exceptions = SecTrustCopyExceptions(serverTrust)
            /// Задает список исключений, которые следует игнорировать при оценке сертификата
            SecTrustSetExceptions(serverTrust, exceptions)
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            /// Обработка вызова по умолчанию — как если бы этот делегат не был реализован
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

extension WebimServerTrustPolicy {
    /// Проверка валдиности соединения
    /// - Parameters:
    ///   - trust: Объект, используемый для оценки доверия
    ///   - host: Хост
    ///   - validHost: Корректный хост
    /// - Returns: Валидно
    private func validConnection(trust: SecTrust,
                         host: String?,
                         validHost: [String]?) -> Bool {
        /// Получаем публичные  ключи приложения
        let applicationSecKeys = WebimServerTrustPolicyManager.shared.getSecKeys()
        var serverTrustIsValid = false
        /// Получаем публичные ключи из оцениваемой цепочке сертификатов от сервера
        outerLoop: for serverPublicKey in self.publicKeys(for: trust) as [AnyObject] {
            /// Получаем публичные ключи зашитые в приложении
            for pinnedPublicKey in applicationSecKeys as [AnyObject] {
                /// Сравниваем публичные ключи
                if serverPublicKey.isEqual(pinnedPublicKey) {
                    serverTrustIsValid = true
                    break outerLoop
                }
            }
        }
        /// Валидируем хост
        if serverTrustIsValid, let _host = host, let _validHost = validHost {
            serverTrustIsValid = self.hostIsValid(validHost: _validHost, host: _host)
        }
        /// Валидируем домен сертификата и хост
        if serverTrustIsValid, let _host = host {
            serverTrustIsValid = self.validateHostAndDomainCertificate(for: trust, host: _host)
        }
        return serverTrustIsValid
    }
    
    /// Проверка валидности хоста
    /// - Parameter host: Хост
    /// - Parameter validHosts: Валидные хосты
    /// - Returns: Bool
    private func hostIsValid(validHost: [String], host: String) -> Bool {
        var contains = false
        validHost.forEach { element in
            if element.contains(host) {
                contains = true
            }
        }
        return contains
    }
    
    /// Получить публичный ключ сертификата
    /// - Returns: SecKey?
    private func getCAPublicKey(_ caCertificate: String) -> SecKey? {
        if let data = Data(base64Encoded: caCertificate), let certificate = SecCertificateCreateWithData(nil, data as CFData), let publicKey = self.publicKey(for: certificate) {
            return publicKey
        } else {
            return nil
        }
    }
    
    /// Получить публичный ключ сертификата
    /// - Parameter certificate: SecCertificate
    /// - Returns: SecKey?
    private func publicKey(for certificate: SecCertificate) -> SecKey? {
        var publicKey: SecKey?
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)
        if let trust = trust, trustCreationStatus == errSecSuccess {
            publicKey = SecTrustCopyPublicKey(trust)
        }
        return publicKey
    }
    
    /// Получить публичные ключи для SecTrust
    /// - Parameter trust: SecTrust
    /// - Returns: [SecKey]
    private func publicKeys(for trust: SecTrust) -> [SecKey] {
        var publicKeys: [SecKey] = []
        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let certificate = SecTrustGetCertificateAtIndex(trust, index), let publicKey = self.publicKey(for: certificate) {
                publicKeys.append(publicKey)
            }
        }
        return publicKeys
    }
    
    /// Проверка хоста и домена сертификата
    /// - Parameter trust: SecTrust
    /// - Parameter host: Хост
    /// - Returns: Bool
    private func validateHostAndDomainCertificate(for trust: SecTrust, host: String) -> Bool {
        var valid = false
        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let certificate = SecTrustGetCertificateAtIndex(trust, index) {
                var commonNameRef: CFString?
                if #available(iOS 10.3, *) {
                    SecCertificateCopyCommonName(certificate, &commonNameRef)
                    if let name = commonNameRef as String?, host.contains(self.getCommonNameCertificate(name)) {
                        valid = true
                    }
                } else {
                    let certSummary = SecCertificateCopySubjectSummary(certificate)
                    if let summary = certSummary as String?, host.contains(self.getCommonNameCertificate(summary)) {
                        valid = true
                    }
                }
            }
        }
        return valid
    }
    
    /// Получить общее имя
    /// - Returns: String?
    private func getCommonNameCertificate(_ value: String) -> String {
        return value.replacingOccurrences(of: "*", with: "")
    }
}
