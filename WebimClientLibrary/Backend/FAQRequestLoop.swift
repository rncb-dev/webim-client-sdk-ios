//
//  FAQRequestLoop.swift
//  WebimClientLibrary
//
//  Created by Nikita Kaberov on 07.02.17.
//  Copyright © 2019 Webim. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

import Foundation

/**
 Class that handles HTTP-requests sended by WebimClientLibrary with visitor FAQ actions.
 - author:
 Nikita Kaberov
 - copyright:
 2019 Webim
 */
class FAQRequestLoop: AbstractRequestLoop {
    
    // MARK: - Properties
    private let completionFAQHandlerExecutor: ExecIfNotDestroyedFAQHandlerExecutor
    var operationQueue: OperationQueue?
    
    
    // MARK: - Initialization
    init(completionHandlerExecutor: ExecIfNotDestroyedFAQHandlerExecutor) {
        self.completionFAQHandlerExecutor = completionHandlerExecutor
        super.init(completionHandlerExecutor: nil, internalErrorListener: nil)
    }
    
    // MARK: - Methods
    
    override func start() {
        guard operationQueue == nil else {
            return
        }
        
        operationQueue = OperationQueue()
        operationQueue?.maxConcurrentOperationCount = 1
        operationQueue?.qualityOfService = .userInitiated
    }
    
    override func stop() {
        super.stop()
        
        operationQueue?.cancelAllOperations()
        operationQueue = nil
    }
    
    func enqueue(request: WebimRequest) {
        operationQueue?.addOperation { [weak self] in
            guard let `self` = self else {
                return
            }
            
            if !self.isRunning() {
                return
            }
            
            let parameterDictionary = request.getPrimaryData()
            let parametersString = parameterDictionary.stringFromHTTPParameters()
            
            var url: URL?
            var urlRequest: URLRequest?
            let httpMethod = request.getHTTPMethod()
            if httpMethod == .get {
                url = URL(string: (request.getBaseURLString() + "?" + parametersString))
                urlRequest = URLRequest(url: url!)
            } else { // POST
                
                // For URL encoded requests.
                url = URL(string: request.getBaseURLString())
                urlRequest = URLRequest(url: url!)
                urlRequest!.httpBody = parametersString.data(using: .utf8)
                
                
                // Assuming that content type field is always exists when it is POST request, and does not when request is of GET type.
                urlRequest!.setValue(request.getContentType(),
                                     forHTTPHeaderField: "Content-Type")
            }
            
            urlRequest!.httpMethod = httpMethod.rawValue
            
            do {
                let data = try self.perform(request: urlRequest!)
                if let _ = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                    if let completionHandler = request.getFAQSearchCompletionHandler() {
                        self.completionFAQHandlerExecutor.execute(task: DispatchWorkItem {
                            do {
                                try completionHandler(data)
                            } catch {
                            }
                            self.handleClientCompletionHandlerOf(request: request)
                        })
                    }
                }
                if let _ = try? JSONSerialization.jsonObject(with: data) as? [Int] {
                    if let completionHandler = request.getFAQCategoryRequestCompletionHandler() {
                        self.completionFAQHandlerExecutor.execute(task: DispatchWorkItem {
                            do {
                                try completionHandler(data)
                            } catch {
                            }
                            self.handleClientCompletionHandlerOf(request: request)
                        })
                    }
                }
                if let dataJSON = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    if (dataJSON[AbstractRequestLoop.ResponseFields.error.rawValue] as? String) != nil {
                        self.running = false

                        return
                    }
                    
                    if let completionHandler = request.getFAQItemRequestCompletionHandler() {
                        self.completionFAQHandlerExecutor.execute(task: DispatchWorkItem {
                            do {
                                try completionHandler(data)
                            } catch {
                            }
                            
                        })
                    }
                    
                    if let completionHandler = request.getFAQCategoryRequestCompletionHandler() {
                        self.completionFAQHandlerExecutor.execute(task: DispatchWorkItem {
                            do {
                                try completionHandler(data)
                            } catch {
                            }
                            
                        })
                    }
                    
                    if let completionHandler = request.getFAQStructureRequestCompletionHandler() {
                        self.completionFAQHandlerExecutor.execute(task: DispatchWorkItem {
                            do {
                                try completionHandler(data)
                            } catch {
                            }
                            
                        })
                    }
                    
                    self.handleClientCompletionHandlerOf(request: request)
                }
            } catch let unknownError as UnknownError {
                self.handleRequestLoop(error: unknownError)
            } catch {
            }
        }
    }
    
    // MARK: Private methode
    
    private func handleClientCompletionHandlerOf(request: WebimRequest) {
        completionFAQHandlerExecutor.execute(task: DispatchWorkItem {
            request.getDataMessageCompletionHandler()?.onSuccess(messageID: request.getMessageID()!)
            request.getSendFileCompletionHandler()?.onSuccess(messageID: request.getMessageID()!)
            request.getRateOperatorCompletionHandler()?.onSuccess()
            request.getDeleteMessageCompletionHandler()?.onSuccess(messageID: request.getMessageID()!)
            request.getEditMessageCompletionHandler()?.onSuccess(messageID: request.getMessageID()!)
        })
    }
    
}
